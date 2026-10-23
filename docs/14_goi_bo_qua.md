# C03-T04 — Xử lý packet không hỗ trợ, lỗi và thống kê bỏ qua

Mã nguồn: `src/nids/packets.py` (`inspect_packet()`, `ParseResult`,
`ParseStats`, `extract_packets(path, stats)`). Kiểm thử: `tests/test_packets.py`,
các lớp `SkipReasonTest`, `NoteTest`, `FileTest`. Quyết định liên quan: QĐ-015.

## 1. Nguyên tắc

- Không gói nào bị bỏ đi mà không được đếm. Mỗi gói không dùng được có một lý
  do và một chi tiết, ví dụ `khong_phai_ip` / `ARP (0x0806)`.
- Gói đọc được nhưng có điểm bất thường (bị cắt, phân mảnh, ...) vẫn được giữ
  và được ghi chú, để biết dữ liệu đầu vào của đặc trưng có thiếu gì không.
- Lỗi của một gói không làm dừng cả file. Lỗi cấu trúc file thì dừng đọc nhưng
  giữ các gói trước chỗ hỏng và báo rõ.
- Ghi số thứ tự khung đầu tiên của mỗi lý do để mở được ngay trong Wireshark.

## 2. Lý do bỏ qua một packet

| Mã | Khi nào | Chi tiết ghi kèm |
|---|---|---|
| `khong_phai_ip` | Tầng liên kết đọc được nhưng không chở IPv4/IPv6: ARP, LLDP, STP, khung 802.3/LLC, ... | Tên và giá trị EtherType, `802.3/LLC`, hoặc họ địa chỉ của loopback |
| `linktype_khong_ho_tro` | Kiểu tầng liên kết chưa hỗ trợ, ví dụ 802.11 (105), radiotap (127) | `LINKTYPE <số>` |
| `header_lien_ket_bi_cat` | Gói ngắn hơn header tầng liên kết | `Ethernet`, `VLAN`, `Linux cooked`, ... |
| `header_ip_bi_cat` | Chưa đủ 20 byte (IPv4) hoặc 40 byte (IPv6) header IP | `IPv4` / `IPv6` |
| `header_ip_sai` | Sai phiên bản so với EtherType, IHL nhỏ hơn 20 byte, Total Length nhỏ hơn header | Mô tả lỗi |

Gói ARP không có địa chỉ IP nguồn/đích ở header IP nên không dùng cho flow; nếu
sau này cần phát hiện ARP spoofing thì phải viết bộ đọc riêng.

## 3. Ghi chú trên gói vẫn được giữ

| Mã | Ý nghĩa | Ảnh hưởng |
|---|---|---|
| `bi_cat_snaplen` | `caplen < orig_len`, gói bị cắt khi bắt | `frame_len`, `ip_len` vẫn đúng; payload thiếu |
| `thieu_header_tang_tren` | Giao thức có cổng nhưng không đọc được cổng hoặc cờ TCP vì gói bị cắt hoặc IP không chở đủ header | Các trường cổng/cờ là `None` |
| `phan_manh_ip` | Gói thuộc datagram bị phân mảnh | Mảnh sau không có cổng |
| `ip_len_bang_0` | IPv4 Total Length bằng 0, thường do card mạng chia đoạn (TSO) khi bắt trên chính máy gửi | `ip_len` lấy theo số byte đã bắt, giống Wireshark |
| `ip_len_vuot_khung` | Header IP khai báo dài hơn khung dù gói không bị cắt | Gói giả mạo hoặc hỏng; `ip_len` giữ theo header |
| `khong_co_timestamp` | Simple Packet Block của PCAPNG | `ts_ns` là `None`, không dùng được cho cửa sổ thời gian |

## 4. Lỗi ở mức file

| Tình huống | Xử lý |
|---|---|
| File không tồn tại, không phải PCAP/PCAPNG, header hỏng | Ném ngoại lệ (`OSError`, `PcapFormatError`); không có gói nào để dùng |
| File kết thúc giữa chừng một bản ghi (tcpdump bị dừng đột ngột, copy dở) | Giữ các gói trước đó, `truncated_file = True`, in cảnh báo |
| Bản ghi giữa file bị hỏng (`incl_len` vô lý, giao diện chưa khai báo, ...) | Có `stats`: dừng đọc, giữ các gói trước đó, ghi `file_error`, lệnh dòng lệnh trả mã thoát 1. Không có `stats`: ném `PcapFormatError` |
| Block PCAPNG không chứa packet | Bỏ qua, đếm `skipped_blocks` |
| File không có gói IP nào | Cảnh báo kiểm tra kiểu tầng liên kết |

Khi một bản ghi bị hỏng thì không biết bản ghi kế tiếp bắt đầu ở đâu, nên không
đọc tiếp được; phần còn lại của file phải sửa bằng công cụ khác, ví dụ
`pcapfix`, rồi đọc lại.

## 5. Cách dùng

```python
from nids.packets import ParseStats, extract_packets

stats = ParseStats()
records = list(extract_packets("data/pcap/k1-binh-thuong-train-01.pcap", stats))
print("\n".join(stats.summary_lines()))
run_log["thong_ke_doc_pcap"] = stats.as_dict()   # ghi vào nhật ký lần chạy
```

Dòng lệnh in thống kê sau bảng gói; `--stats` ghi thêm ra JSON:

```bash
python -m nids.packets data/pcap/<file>.pcap --csv output/packets.csv --stats output/packets_stats.json
```

```
Tổng packet: 24764; gói IP: 24407; bỏ qua: 357 (1.44%)
Bỏ qua theo lý do:
  khong_phai_ip: 357 [ARP (0x0806)=357] (khung đầu tiên trong Wireshark: 1792)
Theo giao thức: TCP=24240, UDP=147, ICMP=20
```

Các khóa của JSON: `tong_packet`, `giu_lai`, `bo_qua`, `bo_qua_theo_ly_do`,
`chi_tiet_bo_qua`, `packet_dau_tien_bo_qua` (chỉ số bắt đầu từ 0),
`ghi_chu_goi_giu_lai`, `file_bi_cut`, `block_pcapng_bo_qua`, `loi_file`.

`parse_packet()` vẫn trả về `PacketRecord` hoặc `None` như trước; muốn biết lý
do thì gọi `inspect_packet()`.

## 6. Kiểm tra

**Kiểm thử tự động** (14 ca mới, tổng 64 ca): mỗi lý do bỏ qua và chi tiết của
nó, mỗi loại ghi chú, gói sạch không có ghi chú, đếm thống kê trên file, file
cụt, bản ghi hỏng giữa file (có và không có `stats`, mã thoát của lệnh), xuất
JSON.

**Trên file thật** (ngày 21/10/2026):

| File | Packet | Giữ lại | Bỏ qua | Đối chiếu |
|---|---|---|---|---|
| CTU-13 `donbot.pcap` (cả bản PCAPNG) | 24 764 | 24 407 | 357 ARP | `tshark -Y "!ip && !ipv6"` cho 357 gói, đều EtherType 0x0806; khung 1792 là ARP |
| CTU-13 `sogou.pcap` | 20 663 | 20 614 | 49 ARP | `tshark` cho 49 gói ARP |
| `donbot.pcap` cắt còn một nửa dung lượng | 6 832 | 6 781 | 51 ARP | `capinfos` đọc được 6 832 gói rồi báo file bị cắt giữa chừng |
| `donbot.pcap` sửa `incl_len` của packet thứ 10 001 | 10 000 | 9 922 | 78 ARP | `capinfos` báo lỗi sau 10 000 gói; bộ đọc ghi `file_error`, mã thoát 1 |

Hai bản thu CTU-13 không có gói bị cắt, phân mảnh hay header hỏng, nên các ghi
chú và các lý do còn lại mới được kiểm tra bằng dữ liệu tổng hợp. Cần xem lại
thống kê khi có PCAP lab thật, nhất là `ip_len_bang_0` nếu bắt gói trên chính
máy Kali gửi traffic.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Bỏ qua (skip) | Gói không dùng được nên không đưa vào bảng, nhưng vẫn được đếm |
| Ghi chú (note) | Dấu hiệu bất thường trên gói vẫn được giữ lại |
| EtherType | 2 byte trong header Ethernet cho biết bên trong là gì: IPv4, IPv6, ARP, ... |
| ARP, LLDP, STP | Giao thức hỏi địa chỉ MAC / giao thức thiết bị tự giới thiệu với nhau / giao thức chống vòng lặp của switch; đều không chở IP |
| 802.3/LLC | Kiểu khung Ethernet cũ, thay EtherType bằng độ dài; thường dùng cho giao thức của switch |
| LINKTYPE | Mã kiểu tầng liên kết của file |
| IHL | Trường độ dài header IPv4, tính theo đơn vị 4 byte |
| Total Length | Trường độ dài cả gói IPv4 |
| ARP spoofing | Tấn công gửi trả lời ARP giả để chiếm lưu lượng của máy khác |
| TSO | Card mạng tự chia gói lớn khi gửi; bắt trên chính máy gửi thấy gói chưa chia, Total Length bằng 0 |
| Simple Packet Block | Kiểu khối gói tin tối giản của PCAPNG, không có thời điểm |
| pcapfix | Công cụ sửa file PCAP bị hỏng |
| JSON | Định dạng file chữ lưu dữ liệu có cấu trúc dạng `{"khóa": giá trị}` |
| Mã thoát (exit code) | Số chương trình trả về khi kết thúc: 0 là thành công, khác 0 là có lỗi |
| Ngoại lệ (exception) | Cách Python báo lỗi và dừng việc đang làm, trừ khi có mã bắt lỗi |
| Khung (frame) số N trong Wireshark | Wireshark đánh số gói từ 1; số này bằng chỉ số trong chương trình cộng 1 |
