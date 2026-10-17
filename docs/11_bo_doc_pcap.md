# C03-T01 — Bộ đọc PCAP theo từng packet

Mã nguồn: `src/nids/pcap_reader.py`. Kiểm thử: `tests/test_pcap_reader.py`.
Quyết định liên quan: QĐ-013.

## 1. Chức năng

Bộ đọc mở một file PCAP hoặc PCAPNG và trả về lần lượt từng packet. Mỗi packet
là một `RawPacket`:

| Trường | Ý nghĩa |
|---|---|
| `index` | Thứ tự trong file, bắt đầu từ 0 |
| `ts_ns` | Thời điểm bắt, nano giây từ epoch UTC (số nguyên, không mất độ chính xác) |
| `ts` | Như trên, tính bằng giây (float) |
| `caplen` | Số byte đã lưu (`incl_len`) |
| `origlen` | Độ dài gói trên đường truyền (`orig_len`); dùng cho đặc trưng dung lượng |
| `truncated` | `True` khi gói bị cắt lúc bắt (`caplen < origlen`) |
| `linktype` | Mã LINKTYPE, cho biết byte đầu của `data` thuộc header nào |
| `data` | Byte thô của gói, tính từ header tầng liên kết |
| `interface` | Chỉ số giao diện; với PCAP luôn là 0 |

Bộ đọc chỉ tách bản ghi khỏi file. Việc đọc header Ethernet, IP, TCP/UDP là
task C03-T02 và C03-T03.

## 2. Cách dùng

```python
from nids.pcap_reader import PcapReader

with PcapReader("data/pcap/k1-binh-thuong-train-01.pcap") as reader:
    for pkt in reader:
        print(pkt.index, pkt.ts_ns, pkt.origlen, pkt.linktype)
    print(reader.format, reader.packets_read, reader.truncated_file)
```

Xem nhanh một file từ dòng lệnh:

```bash
python -m nids.pcap_reader data/pcap/<file>.pcap -n 10
```

Lệnh in 10 packet đầu, định dạng file, các giao diện, số packet, tổng độ dài
gốc và khoảng thời gian.

## 3. Định dạng hỗ trợ

| Định dạng | Hỗ trợ |
|---|---|
| PCAP micro giây và nano giây, little-endian và big-endian | Có |
| PCAPNG: Section Header, Interface Description, Enhanced Packet Block | Có |
| PCAPNG: Simple Packet Block | Có; packet không có timestamp (`ts_ns = None`) |
| PCAPNG: Packet Block kiểu cũ | Có |
| PCAPNG: nhiều giao diện, nhiều section, thứ tự byte khác nhau giữa các section | Có |
| PCAPNG: độ phân giải timestamp `if_tsresol` và độ lệch `if_tsoffset` | Có |
| Các block PCAPNG khác (thống kê, phân giải tên, khóa giải mã, ...) | Bỏ qua, đếm trong `skipped_blocks` |
| File nén (`.gz`) | Không |

Định dạng được nhận biết qua 4 byte đầu file, không theo phần mở rộng.

## 4. Xử lý lỗi

| Tình huống | Cách xử lý |
|---|---|
| 4 byte đầu không phải PCAP/PCAPNG | Báo `PcapFormatError` |
| Header file thiếu byte | Báo `PcapFormatError` |
| Bản ghi khai báo độ dài lớn bất thường (trên 262144 byte và trên `snaplen`) | Báo `PcapFormatError`: file hỏng |
| Packet tham chiếu giao diện chưa khai báo | Báo `PcapFormatError` |
| File kết thúc giữa chừng một bản ghi (ví dụ tcpdump bị dừng đột ngột) | Dừng đọc, giữ các packet trước đó, đặt `truncated_file = True` |

Xử lý packet không hỗ trợ ở tầng giao thức và thống kê số packet bỏ qua là
task C03-T04.

## 5. Kiểm tra

**Kiểm thử tự động** (`tests/test_pcap_reader.py`, 12 ca):

- Đọc đúng file ví dụ 82 byte trong [04_dinh_dang_pcap.md](04_dinh_dang_pcap.md).
- PCAP big-endian, nano giây, gói bị cắt, file chỉ có header, file cụt, file
  hỏng.
- PCAPNG hai giao diện khác kiểu liên kết và độ phân giải, section big-endian,
  Simple Packet Block, nhiều section, giao diện chưa khai báo.
- Lệnh xem nhanh từ dòng lệnh.

**Đối chiếu với Wireshark** (ngày 17/10/2026, TShark của Wireshark cài trên
máy phát triển): dùng file thật `botnet-capture-20110816-donbot.pcap` của
CTU-13 scenario 6 (5,3 MB, 24 764 packet). Từ file này tạo thêm bản PCAPNG và
bản PCAP nano giây bằng `editcap`. Với cả ba file, timestamp, `orig_len` và
`incl_len` của **mọi** packet khớp với kết quả `tshark`, và byte dữ liệu của ba
file giống nhau. Đối chiếu chi tiết từng trường giao thức với Wireshark là task
C03-T07.

**Tốc độ:** khoảng 300 000 packet/giây trên file tổng hợp 1 000 000 packet
(600 MB) trên máy phát triển. Một file PCAP 10 GB của CIC-IDS2017 cỡ vài chục
triệu packet sẽ mất vài phút chỉ để đọc. Đây là số đo trên dữ liệu tổng hợp,
chưa đo trên file CIC-IDS2017 thật.
