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
                                           "allow_egress": ["jhu.instructure.com"]})):
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

    def test_airgap_forwards_nothing_and_has_no_nat(self):
        n = ap.render(policy(passphrase="s3cret"))["nftables.conf"]
        self.assertIn("type filter hook forward priority filter; policy drop;", n)
        self.assertNotIn("masquerade", n, "airgap must have no NAT at all")
        self.assertNotIn("themis_nat", n)

    def test_allowlist_adds_nat_and_named_egress_only(self):
        n = ap.render(policy(profile="allowlist", passphrase="s3cret",
                             uplink_interface="eth0",
                             allow_egress=["jhu.instructure.com"]))["nftables.conf"]
        self.assertIn("masquerade", n)
        self.assertIn("jhu.instructure.com", n)
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
                             allow_egress=["a.example.com", "b.example.com"]))["nftables.conf"]
        self.assertIn("ip daddr { a.example.com, b.example.com }", n)
        self.assertIn("tcp dport { 80, 443 }", n)
