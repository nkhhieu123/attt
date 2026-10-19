"""Trích xuất timestamp, IP, giao thức và độ dài từ từng packet (C03-T02).

Nhận RawPacket của pcap_reader, bóc header tầng liên kết rồi đọc header IPv4
hoặc IPv6. Packet không phải IP, hoặc header IP bị cắt/không hợp lệ, cho kết
quả None; việc phân loại và đếm các packet này là task C03-T04. Cổng và cờ TCP
là task C03-T03.

    for rec in extract_packets("data/pcap/k1-binh-thuong-train-01.pcap"):
        print(rec.ts_ns, rec.src_ip, rec.dst_ip, rec.protocol_name, rec.frame_len)
"""

import argparse
import csv
import socket
import struct
import sys
from dataclasses import asdict, dataclass
from ipaddress import IPv6Address

from .pcap_reader import PcapReader, RawPacket

# Mã LINKTYPE được hỗ trợ (xem docs/04_dinh_dang_pcap.md, mục 2)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = (0x8100, 0x88A8, 0x9100)  # 802.1Q, 802.1ad (QinQ)

# Giá trị họ địa chỉ trong header loopback BSD (LINKTYPE_NULL)
NULL_AF_INET = 2
NULL_AF_INET6 = (10, 24, 28, 30)  # Linux, NetBSD/OpenBSD, FreeBSD, macOS

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58
PROTOCOL_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP",
    51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

# Header mở rộng của IPv6 có dạng (next header, độ dài) ở 2 byte đầu
IPV6_EXT_HOP_BY_HOP = 0
IPV6_EXT_ROUTING = 43
IPV6_EXT_FRAGMENT = 44
IPV6_EXT_AH = 51
IPV6_EXT_DEST_OPTS = 60
IPV6_NO_NEXT = 59


@dataclass(frozen=True)
class PacketRecord:
    index: int            # thứ tự packet trong file
    ts_ns: int | None     # thời điểm bắt, nano giây từ epoch UTC
    src_ip: str
    dst_ip: str
    ip_version: int       # 4 hoặc 6
    protocol: int         # số hiệu giao thức tầng trên (6 = TCP, 17 = UDP, ...)
    frame_len: int        # độ dài gói trên đường truyền (orig_len), gồm cả header liên kết
    ip_len: int           # độ dài gói IP theo header IP (IPv4 total length; IPv6 40 + payload length)
    caplen: int           # số byte đã lưu trong file
    l4_offset: int | None  # vị trí header tầng trên trong data; None với mảnh IP không phải mảnh đầu
    is_fragment: bool     # gói thuộc một datagram IP bị phân mảnh

    @property
    def protocol_name(self) -> str:
        return PROTOCOL_NAMES.get(self.protocol, str(self.protocol))

    @property
    def ts(self) -> float | None:
        return None if self.ts_ns is None else self.ts_ns / 1e9


def network_offset(linktype: int, data: bytes) -> tuple[int, int] | None:
    """Tìm header tầng mạng: trả về (vị trí bắt đầu, phiên bản IP) hoặc None."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        pos = 12
        ethertype = struct.unpack_from("!H", data, pos)[0]
        while ethertype in ETHERTYPE_VLAN:
            pos += 4
            if len(data) < pos + 2:
                return None
            ethertype = struct.unpack_from("!H", data, pos)[0]
        return _from_ethertype(ethertype, pos + 2)
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        return _from_ethertype(struct.unpack_from("!H", data, 14)[0], 16)
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None
        return _from_ethertype(struct.unpack_from("!H", data, 0)[0], 20)
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None
        # Họ địa chỉ ghi theo thứ tự byte của máy bắt gói; thử cả hai chiều.
        for fmt in ("<I", ">I"):
            family = struct.unpack_from(fmt, data, 0)[0]
            if family == NULL_AF_INET:
                return 4, 4
            if family in NULL_AF_INET6:
                return 4, 6
        return None
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not data:
            return None
        version = data[0] >> 4
        return (0, version) if version in (4, 6) else None
    return None


def _from_ethertype(ethertype, pos):
    if ethertype == ETHERTYPE_IPV4:
        return pos, 4
    if ethertype == ETHERTYPE_IPV6:
        return pos, 6
    return None


def parse_packet(pkt: RawPacket) -> PacketRecord | None:
    """Trích xuất các trường IP của một packet; None nếu không phải gói IP đọc được."""
    found = network_offset(pkt.linktype, pkt.data)
    if found is None:
        return None
    pos, version = found
    if version == 4:
        fields_ = _parse_ipv4(pkt.data, pos)
    else:
        fields_ = _parse_ipv6(pkt.data, pos)
    if fields_ is None:
        return None
    src, dst, proto, ip_len, l4_offset, is_fragment = fields_
    return PacketRecord(pkt.index, pkt.ts_ns, src, dst, version, proto,
                        pkt.origlen, ip_len, pkt.caplen, l4_offset, is_fragment)


def _parse_ipv4(data, pos):
    if len(data) < pos + 20:
        return None
    ver_ihl, _tos, total_len, _ident, flags_frag, _ttl, proto = struct.unpack_from(
        "!BBHHHBB", data, pos
    )
    ihl = (ver_ihl & 0x0F) * 4
    if ver_ihl >> 4 != 4 or ihl < 20 or total_len < ihl:
        return None
    frag_offset = flags_frag & 0x1FFF
    more_fragments = bool(flags_frag & 0x2000)
    src = socket.inet_ntoa(data[pos + 12:pos + 16])
    dst = socket.inet_ntoa(data[pos + 16:pos + 20])
    l4_offset = pos + ihl if frag_offset == 0 else None
    return src, dst, proto, total_len, l4_offset, more_fragments or frag_offset > 0


def _parse_ipv6(data, pos):
    if len(data) < pos + 40:
        return None
    if data[pos] >> 4 != 6:
        return None
    payload_len, next_header = struct.unpack_from("!HB", data, pos + 4)
    src = IPv6Address(data[pos + 8:pos + 24]).compressed
    dst = IPv6Address(data[pos + 24:pos + 40]).compressed
    offset = pos + 40
    is_fragment = False
    first_fragment = True
    # Đi qua các header mở rộng để tới giao thức tầng trên.
    while next_header in (IPV6_EXT_HOP_BY_HOP, IPV6_EXT_ROUTING, IPV6_EXT_FRAGMENT,
                          IPV6_EXT_AH, IPV6_EXT_DEST_OPTS):
        if len(data) < offset + 8:
            # Header mở rộng bị cắt: vẫn biết địa chỉ nhưng không biết giao thức.
            return src, dst, next_header, 40 + payload_len, None, is_fragment
        nxt, hdr_len = data[offset], data[offset + 1]
        if next_header == IPV6_EXT_FRAGMENT:
            is_fragment = True
            frag_offset = struct.unpack_from("!H", data, offset + 2)[0] >> 3
            first_fragment = frag_offset == 0
            size = 8
        elif next_header == IPV6_EXT_AH:
            size = (hdr_len + 2) * 4
        else:
            size = (hdr_len + 1) * 8
        next_header = nxt
        offset += size
        if not first_fragment:
            break
    l4_offset = offset if first_fragment and next_header != IPV6_NO_NEXT else None
    return src, dst, next_header, 40 + payload_len, l4_offset, is_fragment


def extract_packets(path):
    """Duyệt các gói IP của một file PCAP/PCAPNG; bỏ qua gói không đọc được."""
    with PcapReader(path) as reader:
        for pkt in reader:
            rec = parse_packet(pkt)
            if rec is not None:
                yield rec


CSV_COLUMNS = ("index", "ts", "src_ip", "dst_ip", "ip_version", "protocol",
               "protocol_name", "frame_len", "ip_len", "caplen", "is_fragment")


def _csv_row(rec):
    row = asdict(rec)
    row["ts"] = "" if rec.ts_ns is None else f"{rec.ts_ns // 10**9}.{rec.ts_ns % 10**9:09d}"
    row["protocol_name"] = rec.protocol_name
    row["is_fragment"] = int(rec.is_fragment)
    return {col: row[col] for col in CSV_COLUMNS}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Trích xuất timestamp, IP, giao thức, độ dài từ file PCAP/PCAPNG."
    )
    parser.add_argument("file", help="đường dẫn file .pcap hoặc .pcapng")
    parser.add_argument("--csv", help="ghi bảng packet ra file CSV")
    parser.add_argument("-n", "--count", type=int, default=10,
                        help="số gói IP đầu tiên được in (mặc định: %(default)s)")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    total = ip_count = 0
    by_proto = {}
    out = writer = None
    try:
        if args.csv:
            out = open(args.csv, "w", encoding="utf-8", newline="")
            writer = csv.DictWriter(out, fieldnames=CSV_COLUMNS)
            writer.writeheader()
        with PcapReader(args.file) as reader:
            for pkt in reader:
                total += 1
                rec = parse_packet(pkt)
                if rec is None:
                    continue
                if ip_count < args.count:
                    row = _csv_row(rec)
                    print(f"{rec.index:>6}  {row['ts']}  {rec.src_ip} -> {rec.dst_ip}"
                          f"  {rec.protocol_name}  frame={rec.frame_len} ip={rec.ip_len}")
                ip_count += 1
                by_proto[rec.protocol_name] = by_proto.get(rec.protocol_name, 0) + 1
                if writer:
                    writer.writerow(_csv_row(rec))
    finally:
        if out:
            out.close()
    print()
    print(f"Tổng packet: {total}; gói IP: {ip_count}; không phải IP hoặc lỗi: {total - ip_count}")
    print("Theo giao thức: " + ", ".join(
        f"{name}={n}" for name, n in sorted(by_proto.items(), key=lambda x: -x[1])))
    if args.csv:
        print(f"Đã ghi CSV: {args.csv}")


if __name__ == "__main__":
    main()
