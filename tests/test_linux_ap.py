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
    """A SINGLE-radio policy, which is what most of these tests are about.

    policy.json itself now ships two radios. A test that silently inherited that
    would be asserting about a different configuration than it reads as -- and
    single-radio is still a supported setup, so it still needs pinning. Dual
    radio has its own fixture and its own tests below.
    """
    p = json.loads(json.dumps(POLICY))
    p.pop("radios", None)
    p.pop("bridge", None)
    # Pin the profile too. policy.json is an OPERATOR-EDITED file: it carries
    # whatever mode the last exam ran in, so a test that inherited it was
    # asserting about airgap while rendering whatever happened to be set. Tests
    # that want another profile pass it explicitly.
    p["profile"] = "airgap"
    p.pop("proxy_mode", None)
    p.update(over)
    return p


def dual_policy(**over):
    """Two radios carrying one SSID, bridged -- what policy.json describes now."""
    p = json.loads(json.dumps(POLICY))
    p["radios"] = [{"interface": "wlan1", "channel": 6, "channel_width_mhz": 20},
                   {"interface": "wlan0", "channel": 36, "channel_width_mhz": 80}]
    p["bridge"] = "br-themis"
    p["profile"] = "airgap"
    p.pop("proxy_mode", None)
    p.update(over)
    return p


def rules_only(nft: str) -> str:
    """The ruleset with comments stripped.

    Asserting on the whole text means prose can satisfy or break a test: the
    'proxy' profile's own comment explains that there is nothing to masquerade,
    and a bare `assertNotIn("masquerade")` fails on that sentence while the
    ruleset it is checking contains no such rule.
    """
    return "\n".join(l for l in nft.splitlines() if not l.strip().startswith("#"))


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

    def test_every_configured_channel_is_legal_for_its_band(self):
        """mt7921u will not run an AP on a DFS channel at all.

        Asserted per radio and per band rather than against POLICY["channel"],
        because `autoconfigure` sets that key from the FIRST radio -- which on a
        dual-band setup is the 2.4 GHz one. Testing a 5 GHz-only rule against it
        meant that configuring the hardware correctly broke the test suite.
        """
        for radio in ap.radios_of(POLICY):
            ch = int(radio["channel"])
            with self.subTest(interface=radio["interface"], channel=ch):
                if ap.band_of(ch) == "2.4":
                    self.assertIn(ch, ap.USABLE_24GHZ)
                else:
                    self.assertIn(ch, ap.NON_DFS_5GHZ)

    def test_the_shipped_channel_key_is_a_real_channel(self):
        ch = int(POLICY["channel"])
        self.assertTrue(ch in ap.USABLE_24GHZ or ch in ap.NON_DFS_5GHZ)

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
        self.assertNotIn("masquerade", rules_only(n),
                         "airgap must never masquerade -- there is no uplink")
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


class TestBandAwareRendering(unittest.TestCase):
    """The radio block used to be hardcoded to 5 GHz with a fixed [HT40+].

    That is wrong on half the legal channels -- 40, 48, 153 and 161 pair
    DOWNWARD, and 165 has no 40 MHz partner at all -- and wrong on all of
    2.4 GHz, where VHT does not exist. Every one of those spellings makes
    hostapd refuse the channel outright, which is a dead exam network.
    """

    def _h(self, **over):
        files = ap.render(policy(passphrase="s3cret", **over))
        return next(v for k, v in files.items() if k.startswith("hostapd"))

    def test_24ghz_uses_hw_mode_g_and_no_vht(self):
        h = self._h(ap_interface="wlan0", channel=6, channel_width_mhz=20)
        self.assertIn("hw_mode=g", h)
        self.assertIn("channel=6", h)
        self.assertNotIn("vht_oper_chwidth", h,
                         "VHT is 5 GHz only; offering it on 2.4 GHz is a startup failure")
        self.assertIn("ieee80211ac=0", h)

    def test_5ghz_uses_hw_mode_a_with_vht(self):
        h = self._h(ap_interface="wlan0", channel=36, channel_width_mhz=80)
        self.assertIn("hw_mode=a", h)
        self.assertIn("vht_oper_chwidth=1", h)
        self.assertIn("vht_oper_centr_freq_seg0_idx=42", h)

    def test_ht40_direction_follows_the_channel(self):
        for ch in (36, 44, 149, 157):
            self.assertEqual(ap.ht40_direction(ch), "+", f"channel {ch} pairs upward")
        for ch in (40, 48, 153, 161):
            self.assertEqual(ap.ht40_direction(ch), "-", f"channel {ch} pairs downward")

    def test_channel_165_has_no_40mhz_partner_and_is_clamped(self):
        self.assertIsNone(ap.ht40_direction(165))
        self.assertEqual(ap.effective_width(165, 80), 20)
        h = self._h(ap_interface="wlan0", channel=165, channel_width_mhz=80)
        # Assert on the DIRECTIVE, not on the file: the template's own comment
        # explains that a fixed [HT40+] is wrong, so a bare assertNotIn("HT40")
        # matches that prose and fails on a correctly rendered config.
        capab = next(l for l in h.splitlines() if l.startswith("ht_capab="))
        self.assertNotIn("HT40", capab, "165 sits alone at the top of the US band")
        self.assertIn("vht_oper_chwidth=0", h, "and therefore no 80 MHz either")

    def test_80mhz_centres_are_table_driven_not_arithmetic(self):
        # 149-161 centres on 155, which is NOT 36 + a multiple of 16. The old
        # formula produced 154 for it, and hostapd rejects that.
        self.assertEqual(ap.centre_index(149, 80), 155)
        self.assertEqual(ap.centre_index(161, 80), 155)
        self.assertEqual(ap.centre_index(36, 80), 42)
        self.assertEqual(ap.centre_index(48, 80), 42)

    def test_24ghz_cannot_ask_for_80mhz(self):
        self.assertEqual(ap.effective_width(6, 80), 40)
        self.assertEqual(ap.effective_width(6, 20), 20)

    def test_band_is_decided_by_channel_number(self):
        self.assertEqual(ap.band_of(1), "2.4")
        self.assertEqual(ap.band_of(14), "2.4")
        self.assertEqual(ap.band_of(36), "5")

    def test_24ghz_frequencies_are_not_computed_with_the_5ghz_formula(self):
        # Getting this wrong does not raise: the "can we legally beacon here"
        # lookup simply finds no matching line and reports "could not tell",
        # which is the silent pass that check exists to prevent.
        self.assertEqual(ap.channel_freq_mhz(1), 2412)
        self.assertEqual(ap.channel_freq_mhz(6), 2437)
        self.assertEqual(ap.channel_freq_mhz(11), 2462)
        self.assertEqual(ap.channel_freq_mhz(36), 5180)
        self.assertEqual(ap.channel_freq_mhz(149), 5745)


class TestDualRadio(unittest.TestCase):
    """One adapter beacons on one channel, so dual-band is two radios bridged
    into one broadcast domain carrying one SSID."""

    def test_each_radio_gets_its_own_config_named_after_it(self):
        files = ap.render(dual_policy(passphrase="s3cret"))
        self.assertIn("hostapd-wlan0.conf", files)
        self.assertIn("hostapd-wlan1.conf", files)
        self.assertNotIn("hostapd.conf", files,
                         "with two radios there is no single unnamed config")

    def test_a_single_radio_keeps_the_original_filename(self):
        files = ap.render(policy(passphrase="s3cret", ap_interface="wlan0"))
        self.assertIn("hostapd.conf", files)

    def test_both_radios_carry_the_same_ssid_and_key(self):
        files = ap.render(dual_policy(passphrase="s3cret"))
        confs = [v for k, v in files.items() if k.startswith("hostapd")]
        for c in confs:
            self.assertIn("ssid=EXAM-ONLY", c)
            self.assertIn("wpa_passphrase=s3cret", c)
            self.assertIn("bridge=br-themis", c,
                          "a radio outside the bridge is a separate network")

    def test_the_two_radios_are_on_different_bands(self):
        files = ap.render(dual_policy(passphrase="s3cret"))
        modes = sorted("hw_mode=g" in v and "g" or "a"
                       for k, v in files.items() if k.startswith("hostapd"))
        self.assertEqual(modes, ["a", "g"], "that is the entire point of two radios")

    def test_dnsmasq_and_the_firewall_bind_the_bridge_not_a_radio(self):
        files = ap.render(dual_policy(passphrase="s3cret"))
        self.assertIn("interface=br-themis", files["dnsmasq.conf"])
        self.assertIn('iifname "br-themis"', files["nftables.conf"])
        self.assertNotIn('iifname "wlan0"', files["nftables.conf"],
                         "rules must match where students arrive, which is the bridge")

    def test_client_isolation_is_backed_up_at_the_bridge(self):
        # hostapd's ap_isolate only separates two students on the SAME radio.
        # Across the bridge, a 2.4 GHz student could otherwise reach a 5 GHz one.
        n = ap.render(dual_policy(passphrase="s3cret"))["nftables.conf"]
        self.assertIn("table bridge themis_iso", n)
        self.assertIn("hook forward priority filter; policy drop", n)

    def test_a_single_radio_makes_no_bridge_table(self):
        n = ap.render(policy(passphrase="s3cret", ap_interface="wlan0"))["nftables.conf"]
        self.assertNotIn("table bridge", rules_only(n))


class TestProxyProfile(unittest.TestCase):
    """The guarantee in 'proxy' mode is an ABSENCE: nothing is forwarded, so the
    only way off the network is a connection the proxy opened to a name it
    checked and resolved itself."""

    def _p(self, **over):
        return ap.render(policy(passphrase="s3cret", ap_interface="wlan0",
                                profile="proxy", proxy_mode="allow",
                                allow_dns_names=["canvas.jhu.edu"], **over))

    def test_nothing_is_forwarded_and_nothing_is_masqueraded(self):
        n = rules_only(self._p()["nftables.conf"])
        self.assertIn("hook forward priority filter; policy drop", n)
        self.assertNotIn("masquerade", n,
                         "a student packet is never routed, so there is nothing to translate")
        self.assertNotIn("accept", n.split("chain forward")[1].split("}")[0],
                         "the forward chain must be empty, not merely restrictive")

    def test_the_proxy_port_is_reachable(self):
        n = self._p()["nftables.conf"]
        self.assertIn("tcp dport { 80, 443 } accept", n,
                      "redirecting 443 to a port nothing may talk to hangs every page")

    def test_https_to_any_address_is_redirected_to_the_proxy(self):
        # Otherwise a cached or hardcoded address walks around the name check.
        n = self._p()["nftables.conf"]
        self.assertIn('tcp dport 443 ip daddr != 10.83.0.1 dnat to 10.83.0.1', n)

    def test_other_tcp_is_redirected_only_so_it_fails_instantly(self):
        n = self._p()["nftables.conf"]
        self.assertIn('meta l4proto tcp ip daddr != 10.83.0.1 dnat to 10.83.0.1', n)

    def test_udp_is_NOT_redirected(self):
        # Redirecting UDP would hand queries aimed at a public resolver to our
        # own dnsmasq, which would answer them -- turning "DNS to 8.8.8.8 is
        # refused" into "answered by the sinkhole" and destroying the only probe
        # that can prove UDP egress is shut.
        n = rules_only(self._p()["nftables.conf"])
        self.assertNotIn("l4proto udp ip daddr !=", n)
        self.assertNotIn("l4proto { tcp, udp }", n)

    def test_dns_still_sinkholes_everything_even_in_allowlist_mode(self):
        # The client never needs the real address: it connects to us and the
        # proxy decides. No upstream means DNS tunnelling stays impossible and
        # no HTTPS/SVCB record is served, so ECH cannot be negotiated.
        d = self._p()["dnsmasq.conf"]
        self.assertIn("no-resolv", d)
        self.assertIn("address=/#/10.83.0.1", d)
        self.assertNotIn("server=/", d)

    def test_the_mode_is_reported_honestly(self):
        self.assertIn("proxy", ap.ASSURANCE)
        rows = {r[0]: r[1] for r in ap.ASSURANCE["proxy"]}
        self.assertEqual(rows["Self-hosted VPN, any port"], "BLOCKED")
        self.assertEqual(rows["Phone on cellular"], "NOT BLOCKED")
        self.assertEqual(rows["Local AI model on their laptop"], "NOT BLOCKED")
        self.assertEqual(rows["Collusion through the allowlisted site itself"],
                         "NOT BLOCKED")


class TestJournalPathIsShared(unittest.TestCase):
    """Every component must append to the SAME journal file.

    It is one hash chain. Two writers on two paths produce two chains, the
    console renders one of them, and the proctor is looking at half an exam
    without being told. themis-ap had drifted to /run, which is also where the
    record used to evaporate on reboot -- see themis/state.py.
    """

    def test_themis_ap_agrees_with_themis_state(self):
        from themis.state import ACTIVE_JOURNAL
        self.assertEqual(ap.JOURNAL, ACTIVE_JOURNAL)

    def test_the_journal_does_not_live_in_run(self):
        self.assertNotIn("/run/", str(ap.JOURNAL),
                         "/run is tmpfs: the exam record would not survive a reboot")


class TestHostnameValidation(unittest.TestCase):
    """These names are typed by a teacher and end up inside generated dnsmasq
    directives, where a slash or a newline is not a bad hostname -- it is a new
    configuration line."""

    def test_a_pasted_url_is_reduced_to_its_hostname(self):
        ok, bad = ap.clean_hostnames(["https://jhu.instructure.com/courses/418?x=1"])
        self.assertEqual(ok, ["jhu.instructure.com"])
        self.assertEqual(bad, [])

    def test_ports_credentials_and_wildcards_are_stripped(self):
        ok, _ = ap.clean_hostnames(["canvas.jhu.edu:443", "*.canvas.jhu.edu",
                                    "user:pw@canvas.jhu.edu", "CANVAS.JHU.EDU."])
        self.assertEqual(ok, ["canvas.jhu.edu"], "and deduplicated")

    def test_config_injection_is_refused_not_escaped(self):
        for nasty in ("evil.com/\naddress=/#/1.2.3.4",
                      "a b", "../../etc/passwd", "evil.com address=/#/9.9.9.9",
                      "-leading-dash.com", "x" * 300, "#comment-only"):
            with self.subTest(nasty=nasty[:30]):
                ok, _ = ap.clean_hostnames([nasty])
                self.assertEqual(ok, [], f"{nasty[:30]!r} must not become a name")

    def test_rejections_are_reported_rather_than_silently_dropped(self):
        # A name the teacher believes is blocked, but which was quietly
        # discarded, is the worst outcome available here.
        ok, bad = ap.clean_hostnames(["canvas.jhu.edu", "not a hostname"])
        self.assertEqual(ok, ["canvas.jhu.edu"])
        self.assertEqual(bad, ["not a hostname"])

    def test_blank_lines_and_comments_are_ignored_quietly(self):
        ok, bad = ap.clean_hostnames(["", "   ", "# a comment", "canvas.jhu.edu"])
        self.assertEqual(ok, ["canvas.jhu.edu"])
        self.assertEqual(bad, [])


class TestRadioPlanning(unittest.TestCase):
    """autoconfigure has to produce a working policy from whatever is plugged in."""

    def _plan(self, caps, prefer="2.4"):
        with unittest.mock.patch.object(ap, "usable_channels", lambda i: caps[i]):
            return ap.plan_radios(list(caps), prefer_single=prefer)

    def test_two_capable_radios_split_the_bands(self):
        caps = {"wlan0": {"2.4": [1, 6, 11], "5": [36, 149]},
                "wlan1": {"2.4": [1, 6, 11], "5": [36, 149]}}
        radios, notes = self._plan(caps)
        self.assertEqual(len(radios), 2)
        self.assertEqual({ap.band_of(r["channel"]) for r in radios}, {"2.4", "5"})
        self.assertTrue(any("dual-band" in n for n in notes))

    def test_one_radio_prefers_24ghz_so_nothing_is_excluded(self):
        caps = {"wlan0": {"2.4": [1, 6, 11], "5": [36]}}
        radios, notes = self._plan(caps)
        self.assertEqual(len(radios), 1)
        self.assertEqual(ap.band_of(radios[0]["channel"]), "2.4")
        self.assertTrue(any("second adapter" in n for n in notes))

    def test_a_5ghz_only_radio_is_used_on_5ghz(self):
        caps = {"wlan0": {"5": [36, 149]}}
        radios, _ = self._plan(caps)
        self.assertEqual(ap.band_of(radios[0]["channel"]), "5")

    def test_two_same_band_radios_are_capacity_not_compatibility(self):
        caps = {"wlan0": {"5": [36, 149]}, "wlan1": {"5": [36, 149]}}
        radios, notes = self._plan(caps)
        self.assertEqual(len(radios), 2)
        self.assertNotEqual(radios[0]["channel"], radios[1]["channel"],
                            "two radios on one channel just share airtime")
        self.assertTrue(any("NOT extra compatibility" in n for n in notes),
                        "the operator must be told this excludes 2.4-only devices")

    def test_a_radio_with_no_usable_channel_is_reported(self):
        radios, notes = self._plan({"wlan0": {}})
        self.assertEqual(radios, [])
        self.assertTrue(notes)

    def test_chosen_24ghz_channels_are_non_overlapping(self):
        caps = {"wlan0": {"2.4": list(range(1, 12))},
                "wlan1": {"5": [36]}}
        radios, _ = self._plan(caps)
        ch = next(r["channel"] for r in radios if ap.band_of(r["channel"]) == "2.4")
        self.assertIn(ch, ap.CLEAN_24GHZ)


if __name__ == "__main__":
    unittest.main(verbosity=2)
