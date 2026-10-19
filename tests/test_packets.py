import csv
import io
import struct
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.packets import (
    CSV_COLUMNS, LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL, LINKTYPE_RAW, extract_packets, main, parse_packet,
)
from nids.pcap_reader import RawPacket

MAC_A = bytes.fromhex("080027aabb01")
MAC_B = bytes.fromhex("080027aabb02")
IP_A = bytes([192, 168, 50, 20])
IP_B = bytes([192, 168, 50, 30])
IP6_A = bytes.fromhex("fe800000000000000a0027fffeaabb01")
IP6_B = bytes.fromhex("ff020000000000000000000000000001")


def ipv4(proto=6, payload=b"\0" * 20, flags_frag=0, ihl=5, src=IP_A, dst=IP_B):
    options = b"\0" * ((ihl - 5) * 4)
    total = ihl * 4 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, total, 1, flags_frag, 64, proto, 0,
                       src, dst) + options + payload


def ipv6(next_header=17, payload=b"\0" * 8):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), next_header, 64,
                       IP6_A, IP6_B) + payload


def ether(payload, ethertype=0x0800, vlans=()):
    tags = b"".join(struct.pack("!HH", tpid, vid) for tpid, vid in vlans)
    return MAC_B + MAC_A + tags + struct.pack("!H", ethertype) + payload


def raw(data, linktype=LINKTYPE_ETHERNET, origlen=None, index=0):
    return RawPacket(index, 1_000_000_000, len(data),
                     len(data) if origlen is None else origlen, linktype, data)


class Ipv4Test(unittest.TestCase):
    def test_tcp_over_ethernet(self):
        rec = parse_packet(raw(ether(ipv4())))
        self.assertEqual((rec.src_ip, rec.dst_ip), ("192.168.50.20", "192.168.50.30"))
        self.assertEqual((rec.ip_version, rec.protocol, rec.protocol_name), (4, 6, "TCP"))
        self.assertEqual((rec.frame_len, rec.ip_len), (54, 40))
        self.assertEqual(rec.l4_offset, 34)
        self.assertFalse(rec.is_fragment)
        self.assertEqual(rec.ts_ns, 1_000_000_000)

    def test_ethernet_padding_does_not_change_ip_len(self):
        frame = ether(ipv4(proto=1, payload=b"\0" * 8)) + b"\0" * 18  # khung tối thiểu 60 byte
        rec = parse_packet(raw(frame))
        self.assertEqual((rec.frame_len, rec.ip_len, rec.protocol_name), (60, 28, "ICMP"))

    def test_options_shift_l4_offset(self):
        rec = parse_packet(raw(ether(ipv4(ihl=6))))
        self.assertEqual(rec.l4_offset, 14 + 24)

    def test_vlan_and_qinq(self):
        rec = parse_packet(raw(ether(ipv4(proto=17), vlans=[(0x88A8, 10), (0x8100, 20)])))
        self.assertEqual(rec.protocol_name, "UDP")
        self.assertEqual(rec.l4_offset, 22 + 20)

    def test_fragments(self):
        first = parse_packet(raw(ether(ipv4(flags_frag=0x2000))))
        later = parse_packet(raw(ether(ipv4(flags_frag=185))))
        self.assertTrue(first.is_fragment)
        self.assertEqual(first.l4_offset, 34)
        self.assertTrue(later.is_fragment)
        self.assertIsNone(later.l4_offset)

    def test_snaplen_cut_keeps_frame_len(self):
        frame = ether(ipv4(payload=b"\0" * 1000))
        rec = parse_packet(raw(frame[:96], origlen=len(frame)))
        self.assertEqual((rec.caplen, rec.frame_len, rec.ip_len), (96, 1034, 1020))

    def test_invalid_or_truncated_header(self):
        self.assertIsNone(parse_packet(raw(ether(ipv4())[:30])))
        bad_ihl = bytearray(ether(ipv4()))
        bad_ihl[14] = 0x43
        self.assertIsNone(parse_packet(raw(bytes(bad_ihl))))

    def test_non_ip_is_skipped(self):
        arp = ether(bytes(28), ethertype=0x0806)
        self.assertIsNone(parse_packet(raw(arp)))
        self.assertIsNone(parse_packet(raw(b"\x01\x02")))
        self.assertIsNone(parse_packet(raw(ether(ipv4()), linktype=105)))  # 802.11


class Ipv6Test(unittest.TestCase):
    def test_udp(self):
        rec = parse_packet(raw(ether(ipv6(), ethertype=0x86DD)))
        self.assertEqual((rec.src_ip, rec.dst_ip), ("fe80::a00:27ff:feaa:bb01", "ff02::1"))
        self.assertEqual((rec.ip_version, rec.protocol_name), (6, "UDP"))
        self.assertEqual((rec.ip_len, rec.l4_offset), (48, 54))

    def test_extension_headers(self):
        hop_by_hop = bytes([58, 0]) + bytes(6)            # next = ICMPv6
        rec = parse_packet(raw(ether(ipv6(0, hop_by_hop + bytes(8)), ethertype=0x86DD)))
        self.assertEqual(rec.protocol_name, "ICMPv6")
        self.assertEqual(rec.l4_offset, 14 + 40 + 8)

    def test_fragment_header(self):
        first = bytes([6, 0]) + struct.pack("!HI", 1, 7)              # offset 0, M=1
        later = bytes([6, 0]) + struct.pack("!HI", (100 << 3), 7)     # offset 100
        a = parse_packet(raw(ether(ipv6(44, first + bytes(20)), ethertype=0x86DD)))
        b = parse_packet(raw(ether(ipv6(44, later + bytes(20)), ethertype=0x86DD)))
        self.assertEqual((a.protocol_name, a.is_fragment, a.l4_offset), ("TCP", True, 62))
        self.assertEqual((b.protocol_name, b.is_fragment, b.l4_offset), ("TCP", True, None))


class LinkTypeTest(unittest.TestCase):
    def test_linux_cooked(self):
        sll = struct.pack("!HHH8sH", 0, 1, 6, MAC_A + b"\0\0", 0x0800)
        sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 2, 1, 0, 6, MAC_A + b"\0\0")
        self.assertEqual(parse_packet(raw(sll + ipv4(), LINKTYPE_LINUX_SLL)).l4_offset, 36)
        self.assertEqual(parse_packet(raw(sll2 + ipv4(), LINKTYPE_LINUX_SLL2)).l4_offset, 40)

    def test_loopback_and_raw(self):
        self.assertEqual(parse_packet(raw(struct.pack("<I", 2) + ipv4(), LINKTYPE_NULL)).ip_version, 4)
        self.assertEqual(parse_packet(raw(struct.pack(">I", 30) + ipv6(), LINKTYPE_NULL)).ip_version, 6)
        self.assertEqual(parse_packet(raw(ipv6(), LINKTYPE_RAW)).ip_version, 6)


def pcap_file(path, frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", 100 + i, 5, len(frame), len(frame)) + frame
    path.write_bytes(out)
    return path


class FileTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        arp = ether(bytes(28), ethertype=0x0806)
        self.pcap = pcap_file(self.dir / "t.pcap",
                              [ether(ipv4()), arp, ether(ipv6(), ethertype=0x86DD)])

    def test_extract_skips_non_ip(self):
        recs = list(extract_packets(self.pcap))
        self.assertEqual([r.index for r in recs], [0, 2])
        self.assertEqual([r.protocol_name for r in recs], ["TCP", "UDP"])

    def test_cli_writes_csv(self):
        out_csv = self.dir / "packets.csv"
        with redirect_stdout(io.StringIO()) as out:
            main([str(self.pcap), "--csv", str(out_csv)])
        self.assertIn("Tổng packet: 3; gói IP: 2", out.getvalue())
        with out_csv.open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(tuple(rows[0]), CSV_COLUMNS)
        self.assertEqual(rows[0]["ts"], "100.000005000")
        self.assertEqual(rows[1]["dst_ip"], "ff02::1")


if __name__ == "__main__":
    unittest.main()
