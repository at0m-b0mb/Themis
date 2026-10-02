"""Tests for the Linux exam-AP layer.

hostapd and nft cannot run on the macOS development host, so these tests pin the
things that would otherwise only be discovered on exam day: that every template
placeholder is substituted, that the safety-critical directives are actually
present, and that the 80 MHz centre-frequency arithmetic is right.
"""

import json
import sys
import tempfile
import unittest
import unittest.mock
from importlib.machinery import SourceFileLoader
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from themis.leases import _arp_table_linux  # noqa: E402

ap = SourceFileLoader("themis_ap", str(ROOT / "netguard/linux/bin/themis-ap")).load_module()
POLICY = json.loads((ROOT / "netguard/linux/policy.json").read_text())


def policy(**over):
    p = json.loads(json.dumps(POLICY))
    p.update(over)
    return p


class TestLinuxArp(unittest.TestCase):
    HEADER = "IP address       HW type     Flags       HW address            Mask     Device\n"

    def _arp(self, body, interface=None):
        d = Path(tempfile.mkdtemp()) / "arp"
        d.write_text(self.HEADER + body)
        return _arp_table_linux(interface, d)

    def test_parses_complete_entries(self):
        t = self._arp("10.83.0.51       0x1         0x2         a4:83:e7:1b:2c:3d     *        wlan1\n")
        self.assertEqual(t, {"10.83.0.51": "a4:83:e7:1b:2c:3d"})

    def test_incomplete_entries_are_not_observations(self):
        # Flags 0x0: the kernel asked and got no reply. Treating that as a sighting
        # would invent a device that is not there.
        t = self._arp("10.83.0.99       0x1         0x0         00:00:00:00:00:00     *        wlan1\n")
        self.assertEqual(t, {})

    def test_filters_by_interface(self):
        body = ("10.83.0.51       0x1         0x2         a4:83:e7:1b:2c:3d     *        wlan1\n"
                "192.168.1.9      0x1         0x2         b8:27:eb:00:11:22     *        eth0\n")
        self.assertEqual(set(self._arp(body, "wlan1")), {"10.83.0.51"})
        self.assertEqual(set(self._arp(body)), {"10.83.0.51", "192.168.1.9"})

    def test_missing_file_is_empty(self):
        self.assertEqual(_arp_table_linux(None, "/nonexistent/arp"), {})

    def test_malformed_lines_are_skipped(self):
        t = self._arp("garbage\n10.83.0.51 0x1 notahexflag a4:83:e7:1b:2c:3d * wlan1\n")
        self.assertEqual(t, {})


class TestCentreIndex(unittest.TestCase):
    def test_80mhz_blocks(self):
        # 36-48 is one 80 MHz block centred on 42; 149-161 centres on 155.
        self.assertEqual(ap.centre_index(36, 80), 42)
        self.assertEqual(ap.centre_index(48, 80), 42)
        self.assertEqual(ap.centre_index(149, 80), 155)

    def test_40_and_20mhz(self):
        self.assertEqual(ap.centre_index(36, 40), 38)
        self.assertEqual(ap.centre_index(36, 20), 36)


class TestRender(unittest.TestCase):
    def test_no_placeholder_survives_rendering(self):
        for prof, extra in (("airgap", {}),
                            ("allowlist", {"uplink_interface": "eth0",
                                           "allow_dns_names": ["jhu.instructure.com"],
                                           "allow_egress": ["192.0.2.10"]})):
            with self.subTest(profile=prof):
                files = ap.render(policy(profile=prof, passphrase="s3cret", **extra))
                for name, text in files.items():
                    self.assertNotIn("{{", text, f"{prof}/{name} has an unsubstituted placeholder")
                    self.assertNotIn("}}", text)

    def test_hostapd_enforces_client_isolation(self):
        h = ap.render(policy(passphrase="s3cret"))["hostapd.conf"]
        self.assertIn("ap_isolate=1", h,
                      "client isolation is the first line against answer-sharing")

    def test_hostapd_channel_and_width_are_consistent(self):
        h = ap.render(policy(passphrase="s3cret", channel=36, channel_width_mhz=80))["hostapd.conf"]
        self.assertIn("channel=36", h)
        self.assertIn("vht_oper_centr_freq_seg0_idx=42", h)
        self.assertIn("he_oper_centr_freq_seg0_idx=42", h)
        self.assertIn("ieee80211ax=1", h)

    def test_policy_default_channel_is_non_dfs(self):
        # mt7921u will not run an AP on a DFS channel at all.
        self.assertIn(POLICY["channel"], ap.NON_DFS_5GHZ)

    def test_psk_and_enterprise_are_mutually_exclusive(self):
        psk = ap.render(policy(passphrase="s3cret"))["hostapd.conf"]
        self.assertIn("wpa_key_mgmt=WPA-PSK", psk)
        self.assertNotIn("eap_server", psk)

        ent = policy(passphrase="s3cret",
                     enterprise={"enabled": True, "eap_user_file": "/etc/hostapd/themis.eap_user"})
        e = ap.render(ent)["hostapd.conf"]
        self.assertIn("wpa_key_mgmt=WPA-EAP", e)
        self.assertIn("eap_server=1", e)
        self.assertNotIn("wpa_passphrase", e,
                         "Enterprise mode must not also ship a shared passphrase")

    def test_airgap_forwards_nothing_and_translates_only_to_itself(self):
        # airgap DOES translate now -- the port-80 redirect that makes the captive
        # portal catch a browser holding a cached IP. The invariant is not "no NAT",
        # it is that no translation can ever point off this host.
        n = ap.render(policy(passphrase="s3cret", ap_interface="wlan0",
                             server_ip="10.83.0.1"))["nftables.conf"]
        self.assertIn("type filter hook forward priority filter; policy drop;", n)
        self.assertNotIn("masquerade", n, "airgap must never masquerade -- there is no uplink")
        # Look for the chain, not the word: the comment explaining its absence
        # legitimately contains it.
        self.assertNotIn("type nat hook postrouting", n)
        dnats = [l.strip() for l in n.splitlines() if "dnat to" in l]
        self.assertTrue(dnats, "the portal redirect should be present")
        for d in dnats:
            self.assertIn("dnat to 10.83.0.1", d,
                          f"a translation points somewhere other than this host: {d}")

    def test_http_to_any_address_reaches_the_portal(self):
        n = ap.render(policy(passphrase="s3cret", ap_interface="wlan0"))["nftables.conf"]
        self.assertIn("tcp dport 80 ip daddr != 10.83.0.1 dnat to 10.83.0.1", n)

    def test_students_get_a_reset_not_a_hang(self):
        # A drop makes a student stare at a spinner and conclude the exam network is
        # broken; a reset fails immediately and is what pops the OS sign-in sheet.
        n = ap.render(policy(passphrase="s3cret", ap_interface="wlan0"))["nftables.conf"]
        self.assertIn('iifname "wlan0" meta l4proto tcp reject with tcp reset', n)
        self.assertIn('iifname "wlan0" reject', n)

    def test_no_port_is_advertised_that_nothing_listens_on(self):
        # The portal binds 80. 8080 was open to students with nothing behind it.
        self.assertEqual(POLICY["server_ports"], [80])

    def test_allowlist_adds_nat_and_addressed_egress_only(self):
        n = ap.render(policy(profile="allowlist", passphrase="s3cret",
                             uplink_interface="eth0",
                             allow_egress=["192.0.2.10", "198.51.100.0/24"]))["nftables.conf"]
        self.assertIn("masquerade", n)
        self.assertIn("192.0.2.10", n)
        self.assertIn("198.51.100.0/24", n)
        self.assertIn("policy drop;", n, "forward must still default to drop")

    def test_resolver_has_no_upstream_in_airgap(self):
        d = ap.render(policy(passphrase="s3cret"))["dnsmasq.conf"]
        self.assertIn("no-resolv", d,
                      "no upstream resolver is what makes DNS tunnelling impossible")
        self.assertIn("address=/#/10.83.0.1", d, "every name must sinkhole to the portal")

    def test_netmask_is_derived_from_bits(self):
        d = ap.render(policy(passphrase="s3cret", netmask_bits=24))["dnsmasq.conf"]
        self.assertIn("255.255.255.0", d)
        d = ap.render(policy(passphrase="s3cret", netmask_bits=25))["dnsmasq.conf"]
        self.assertIn("255.255.255.128", d)


class TestBlacklistShipped(unittest.TestCase):
    def test_bt_blacklist_covers_the_mt7921_crash_modules(self):
        txt = (ROOT / "netguard/linux/templates/blacklist-themis-bt.conf").read_text()
        for mod in ap.BT_MODULES:
            self.assertIn(f"blacklist {mod}", txt,
                          f"{mod} must be blacklisted -- it crashes mt7921u Wi-Fi on 6.6+")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestNftSyntaxTraps(unittest.TestCase):
    """nft is unavailable on the macOS dev host, so the syntax rules it would have
    enforced are pinned here instead. Each of these shipped broken once."""

    def test_multiple_ports_are_an_nft_set_not_a_comma_list(self):
        n = ap.render(policy(passphrase="s3cret", server_ports=[80, 8080]))["nftables.conf"]
        self.assertIn("tcp dport { 80, 8080 }", n)
        self.assertNotIn("tcp dport 80, 8080", n,
                         "a bare comma list is a syntax error in nft")

    def test_single_port_still_renders_inside_a_set(self):
        n = ap.render(policy(passphrase="s3cret", server_ports=[80]))["nftables.conf"]
        self.assertIn("tcp dport { 80 }", n)

    def test_icmp_names_its_l3_protocol_in_an_inet_table(self):
        n = ap.render(policy(passphrase="s3cret"))["nftables.conf"]
        self.assertIn("ip protocol icmp icmp type echo-request", n,
                      "inet tables should not rely on nft inferring the ipv4 dependency")

    def test_allowlist_destinations_are_a_set(self):
        n = ap.render(policy(profile="allowlist", passphrase="s3cret",
                             uplink_interface="eth0",
                             allow_egress=["192.0.2.10", "192.0.2.11"]))["nftables.conf"]
        self.assertIn("ip daddr { 192.0.2.10, 192.0.2.11 }", n)
        self.assertIn("tcp dport { 80, 443 }", n)


class TestEgressRefusesHostnames(unittest.TestCase):
    """`nft -c` proved this in a real container: nftables rejects a hostname that
    resolves to multiple addresses -- which is every CDN, Canvas included. Rather
    than emit a config that will not load, the renderer refuses and says why."""

    def _render_allowlist(self, entries):
        return ap.render(policy(profile="allowlist", passphrase="s3cret",
                                uplink_interface="eth0", allow_egress=entries))

    def test_hostname_is_refused(self):
        with self.assertRaises(ap.EgressPolicyError) as cm:
            self._render_allowlist(["jhu.instructure.com"])
        msg = str(cm.exception)
        self.assertIn("jhu.instructure.com", msg)
        self.assertIn("airgap", msg, "the refusal must point at the working alternative")
        self.assertIn("SNI", msg, "and must say why an address allowlist is not enough")

    def test_mixed_list_names_every_offender_and_only_offenders(self):
        with self.assertRaises(ap.EgressPolicyError) as cm:
            self._render_allowlist(["192.0.2.10", "canvas.example.edu", "bad.example"])
        msg = str(cm.exception)
        offenders = msg.split("offending entries:")[1].splitlines()[0]
        self.assertIn("canvas.example.edu", offenders)
        self.assertIn("bad.example", offenders)
        self.assertNotIn("192.0.2.10", offenders,
                         "a valid address must not be reported as an offender")

    def test_addresses_and_cidrs_are_accepted(self):
        n = self._render_allowlist(["192.0.2.10", "198.51.100.0/24"])["nftables.conf"]
        self.assertIn("192.0.2.10", n)

    def test_airgap_never_consults_allow_egress(self):
        # A stale hostname left in the file must not block the safe profile.
        n = ap.render(policy(passphrase="s3cret",
                             allow_egress=["leftover.example.com"]))["nftables.conf"]
        self.assertNotIn("leftover.example.com", n)


class TestTwoListAllowlist(unittest.TestCase):
    """dnsmasq filters names, nftables filters addresses. One list cannot do both,
    and pretending otherwise is how an allowlist silently stops filtering."""

    def _p(self, **over):
        base = dict(profile="allowlist", passphrase="s3cret", uplink_interface="eth0",
                    allow_dns_names=["canvas.example.edu"], allow_egress=["192.0.2.10"])
        base.update(over)
        return policy(**base)

    def test_names_go_to_dnsmasq_addresses_go_to_nftables(self):
        f = ap.render(self._p())
        self.assertIn("server=/canvas.example.edu/", f["dnsmasq.conf"])
        self.assertNotIn("canvas.example.edu", f["nftables.conf"],
                         "a name must never reach the nft ruleset")
        self.assertIn("192.0.2.10", f["nftables.conf"])
        self.assertNotIn("192.0.2.10", f["dnsmasq.conf"])

    def test_dnsmasq_still_sinkholes_everything_else(self):
        d = ap.render(self._p())["dnsmasq.conf"]
        self.assertIn("address=/#/10.83.0.1", d)

    def test_airgap_ignores_both_lists(self):
        f = ap.render(policy(passphrase="s3cret",
                             allow_dns_names=["leftover.example.com"],
                             allow_egress=["192.0.2.10"]))
        self.assertNotIn("leftover.example.com", f["dnsmasq.conf"])
        self.assertNotIn("192.0.2.10", f["nftables.conf"])


class TestBluetoothTrapCheck(unittest.TestCase):
    """The btusb check must answer "can it load", not "has it loaded".

    On the real VM this reported OK purely because the adapter was not attached
    yet -- and attaching an AWUS036AXML, which carries Bluetooth on the same chip,
    is exactly what makes btusb load. A check that passes right up until the moment
    it matters is worse than no check.
    """

    def _blacklist_dir(self, contents: dict[str, str]):
        d = Path(tempfile.mkdtemp())
        for name, text in contents.items():
            (d / name).write_text(text)
        return d

    def test_detects_a_blacklist_entry(self):
        d = self._blacklist_dir({"blacklist-themis-bt.conf": "blacklist btusb\nblacklist btmtk\n"})
        with unittest.mock.patch.object(ap, "pathlib") as m:
            m.Path.return_value = d
            self.assertTrue(ap.bt_blacklisted())

    def test_shipped_blacklist_file_would_satisfy_the_check(self):
        # Parse the file we actually ship the same way the check parses it.
        txt = (ROOT / "netguard/linux/templates/blacklist-themis-bt.conf").read_text()
        entries = {p[1] for p in (l.split("#", 1)[0].split() for l in txt.splitlines())
                   if len(p) >= 2 and p[0] == "blacklist"}
        self.assertIn("btusb", entries)
        self.assertIn("btmtk", entries)

    def test_commented_out_blacklist_does_not_count(self):
        d = self._blacklist_dir({"x.conf": "# blacklist btusb\n"})
        entries = {p[1] for p in (l.split("#", 1)[0].split()
                                  for l in (d / "x.conf").read_text().splitlines())
                   if len(p) >= 2 and p[0] == "blacklist"}
        self.assertNotIn("btusb", entries,
                         "a commented line must not be read as a blacklist")


class TestPreflightNeverCrashes(unittest.TestCase):
    """preflight exists to say what is wrong with a host. If a missing tool makes
    it traceback instead, it fails exactly when it is needed. This shipped once:
    a host without rfkill got a FileNotFoundError instead of a checklist."""

    def test_run_survives_a_missing_binary(self):
        r = ap.run(["definitely-not-a-real-binary-xyz"], check=False)
        self.assertEqual(r.returncode, 127)
        self.assertIsInstance(r.stderr, str)

    def test_out_returns_empty_for_a_missing_binary(self):
        self.assertEqual(ap.out(["definitely-not-a-real-binary-xyz"]), "")

    def test_rfkill_absence_is_unknown_not_false(self):
        with unittest.mock.patch.object(ap.shutil, "which", return_value=None):
            self.assertIsNone(ap.rfkill_blocked("wlan0"),
                              "not knowing must be distinct from knowing it is clear")

    def test_preflight_returns_data_even_with_no_tools_present(self):
        with unittest.mock.patch.object(ap.shutil, "which", return_value=None):
            res = ap.preflight_checks(json.loads((ROOT / "netguard/linux/policy.json").read_text()))
        self.assertIn("ready", res)
        self.assertFalse(res["ready"])
        self.assertTrue(res["fail"], "missing tools must be reported as failures")
        for bucket in ("ok", "warn", "fail"):
            for c in res[bucket]:
                self.assertIsInstance(c["message"], str)


class TestWifiSecurityModes(unittest.TestCase):
    """WPA2-PSK alone has two holes that matter in a room of 19 students:
    unauthenticated deauth frames let any of them disconnect the others, and a
    shared key lets any of them decrypt the others off the air."""

    def _h(self, **over):
        pol = policy(passphrase="demo-passphrase-here", ap_interface="wlan0", **over)
        return ap.render(pol)["hostapd.conf"]

    def test_pmf_is_on_by_default(self):
        # Without 802.11w a student can deauth classmates, and every one of those
        # reads as a genuine drop in the proctor console.
        self.assertIn("ieee80211w=", self._h())
        self.assertNotIn("ieee80211w=0", self._h())

    def test_default_is_wpa2_wpa3_transition(self):
        self.assertEqual(POLICY.get("security"), "wpa2+wpa3")
        h = self._h()
        self.assertIn("wpa_key_mgmt=WPA-PSK SAE", h)
        self.assertIn("sae_password=", h)
        self.assertIn("wpa_passphrase=", h, "older laptops must still be able to join")
        self.assertIn("sae_require_mfp=1", h)

    def test_wpa3_only_forces_pmf_required_and_drops_psk(self):
        h = self._h(security="wpa3")
        self.assertIn("wpa_key_mgmt=SAE", h)
        self.assertIn("ieee80211w=2", h, "WPA3 mandates management-frame protection")
        self.assertNotIn("wpa_passphrase=", h,
                         "SAE-only must not also offer a PSK, or it is not SAE-only")

    def test_wpa2_only_still_available_for_compatibility(self):
        h = self._h(security="wpa2")
        self.assertIn("wpa_key_mgmt=WPA-PSK", h)
        self.assertNotIn("SAE", h)

    def test_an_unknown_security_mode_is_refused(self):
        with self.assertRaises(ap.EgressPolicyError):
            self._h(security="wep")

    def test_pmf_level_is_honoured(self):
        self.assertIn("ieee80211w=2", self._h(pmf=2))


class TestExamNetworkCannotReachTheHost(unittest.TestCase):
    """A student on the exam Wi-Fi must not be able to log into the gateway --
    the journal, the policy and the passphrase all live on it."""

    def test_no_accept_rule_exposes_ssh_or_anything_but_the_portal(self):
        n = ap.render(policy(passphrase="s3cret", ap_interface="wlan0"))["nftables.conf"]
        accepts = [l.strip() for l in n.splitlines()
                   if l.strip().endswith("accept") and "iifname" in l]
        for line in accepts:
            self.assertFalse(
                "dport 22" in line or "dport 3389" in line,
                f"remote-access port reachable from the exam network: {line}")
        self.assertIn("type filter hook input priority filter; policy drop;", n)

    def test_only_the_server_address_is_addressable(self):
        n = ap.render(policy(passphrase="s3cret", ap_interface="wlan0",
                             server_ip="10.83.0.1"))["nftables.conf"]
        for l in n.splitlines():
            s = l.strip()
            if s.startswith("iifname") and s.endswith("accept") and "daddr" in s:
                self.assertIn("ip daddr 10.83.0.1", s,
                              f"an accept rule targets something other than the server: {s}")


class TestNoOverclaimAboutClientIsolation(unittest.TestCase):
    """status used to say student-to-student was blocked by ap_isolate AND by the
    nftables forward chain. The second half is false: two clients of one AP are
    relayed inside the radio at layer 2 and never reach the IP forward hook. If
    ap_isolate is off, nothing else catches it, and saying otherwise would have the
    operator trusting a control that does not exist."""

    def test_status_does_not_claim_the_firewall_backs_up_ap_isolate(self):
        for prof, rows in ap.ASSURANCE.items():
            row = next((r for r in rows if "Student-to-student" in r[0]), None)
            self.assertIsNotNone(row, f"{prof} should still report client isolation")
            why = row[2].lower()
            self.assertIn("ap_isolate", why)
            self.assertIn("does not", why.replace("not reach", "does not reach"))

    def test_client_isolation_is_actually_enabled_in_hostapd(self):
        h = ap.render(policy(passphrase="s3cret", ap_interface="wlan0"))["hostapd.conf"]
        self.assertIn("ap_isolate=1", h,
                      "this is the only thing standing between two students")
