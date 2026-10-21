# C03-T05 — Parser cho access log Nginx

Mã nguồn: `src/nids/service_log.py`. Kiểm thử: `tests/test_service_log.py`.
Định dạng log `nids` và vai trò của log: [05_log_dich_vu.md](05_log_dich_vu.md)
(QĐ-008).

## 1. Chức năng

`read_log(path, stats)` đọc từng dòng của `access_nids.log` (hoặc bản đã xoay
vòng `.gz`) và trả về một `LogRecord` cho mỗi dòng đúng định dạng. Dòng sai bị
bỏ qua kèm lý do, đếm trong `LogStats`. Cách làm giống bộ trích xuất packet
([14_goi_bo_qua.md](14_goi_bo_qua.md)): không dòng nào bị bỏ mà không được đếm.

| Trường | Từ biến Nginx | Kiểu | Ghi chú |
|---|---|---|---|
| `line_no` | | int | Số dòng trong file, bắt đầu từ 1; dùng để đối chiếu với bản gốc (C03-T06) |
| `ts_ns` | `$msec` | int | Nano giây từ epoch UTC, cùng đơn vị với `PacketRecord.ts_ns`; là lúc yêu cầu **kết thúc** |
| `client_ip` | `$remote_addr` | str | IPv6 ở dạng rút gọn chuẩn, giống `packets.py`, để ghép với flow |
| `client_port` | `$remote_port` | int / None | `None` khi Nginx ghi `-` (kết nối qua unix socket) |
| `server_port` | `$server_port` | int | |
| `request` | `$request` | str | Dòng yêu cầu đã giải mã `\xHH` |
| `method`, `target`, `http_version` | tách từ `$request` | str / None | `None` khi dòng yêu cầu không hợp lệ |
| `status` | `$status` | int | |
| `body_bytes` | `$body_bytes_sent` | int | |
| `request_bytes` | `$request_length` | int | |
| `request_time_ms` | `$request_time` | int | Mili giây, số nguyên để không sai số làm tròn |
| `conn_id`, `conn_requests` | `$connection`, `$connection_requests` | int | Các dòng cùng `conn_id` thuộc một kết nối keep-alive |
| `user_agent` | `$http_user_agent` | str / None | `None` khi Nginx ghi `-` |

Thuộc tính tính thêm: `start_ts_ns` (= `ts_ns − request_time`, thời điểm bắt
đầu yêu cầu xấp xỉ), `ts`, `request_time` (giây), `valid_request`.

## 2. Giải mã chuỗi

Với `escape=default`, Nginx thay `"`, `\`, ký tự điều khiển và mọi byte ngoài
ASCII bằng `\xHH`, nên chuỗi trong ngoặc kép không bao giờ chứa `"` thật và mỗi
dòng log luôn là ASCII. Parser đổi `\xHH` về byte rồi giải mã UTF-8:

| Trong log | Sau khi đọc |
|---|---|
| `q=\x22x\x22&t=\x5Cz` | `q="x"&t=\z` |
| `ti\xE1\xBA\xBFng Vi\xE1\xBB\x87t` | `tiếng Việt` |
| `\x16\x03\x01\x00\xA5...` (gói TLS gửi nhầm vào cổng HTTP) | Ký tự điều khiển giữ nguyên; byte không tạo thành UTF-8 hợp lệ giữ dạng chữ `\xa5` |

`target` giữ nguyên mã hóa `%XX` của URL (`/a%20b`), vì đó là thứ client gửi.

## 3. Dòng bỏ qua và ghi chú

| Mã | Khi nào |
|---|---|
| `sai_dinh_dang` | Không khớp đủ 12 trường của `nids`, ví dụ dòng định dạng `combined` khi máy chủ chưa đổi `log_format` |
| `gia_tri_sai` | Khớp định dạng nhưng IP không hợp lệ, cổng ngoài 0–65535, hoặc mã trạng thái ngoài 100–599 |
| `dong_trong` | Dòng trống |
| `dong_cuoi_do_dang` | Dòng cuối không có ký tự xuống dòng và không đọc được: file được sao chép khi Nginx đang ghi |

Ghi chú trên dòng vẫn được giữ:

| Mã | Ý nghĩa |
|---|---|
| `dong_yeu_cau_khong_hop_le` | Dòng yêu cầu không có dạng `METHOD target HTTP/x`: byte nhị phân, yêu cầu dở dang, lệnh lạ. Đây thường là dấu vết quét dò dịch vụ (`nmap -sV`), nên **giữ lại** chứ không bỏ |
| `thoi_gian_giam` | `ts` nhỏ hơn dòng trước. Nginx ghi log khi yêu cầu kết thúc, nên yêu cầu chậm có thể ghi sau yêu cầu nhanh bắt đầu muộn hơn; nhiều worker cũng ghi xen kẽ. Khi ghép với flow phải sắp xếp lại theo thời gian, không giả định log đã có thứ tự |

`LogStats` còn đếm theo mã trạng thái, giữ khoảng thời gian đầu–cuối, số dòng
đầu tiên và tối đa 3 dòng mẫu cho mỗi lý do bỏ qua. Nếu không dòng nào đọc được
thì cảnh báo kiểm tra `log_format` trên máy chủ dịch vụ.

## 4. Cách dùng

```python
from nids.service_log import LogStats, read_log

stats = LogStats()
for rec in read_log("data/service_logs/k1-binh-thuong-train-01/access_nids.log", stats):
    print(rec.client_ip, rec.client_port, rec.start_ts_ns, rec.status, rec.request_time_ms)
print("\n".join(stats.summary_lines()))
run_log["thong_ke_doc_log"] = stats.as_dict()
```

```bash
python -m nids.service_log data/service_logs/<run_id>/access_nids.log -n 10
```

```
     1  2026-10-21T11:15:26.410Z  127.0.0.1:56911 -> :18080  'GET /status HTTP/1.1'  200  0 ms  conn=1/1
     ...
Tổng dòng: 13; đọc được: 13; bỏ qua: 0
Ghi chú: dong_yeu_cau_khong_hop_le=3
Theo mã trạng thái: 200=5, 400=2, 404=3, 408=1, 499=1, 502=1
```

Xuất bảng CSV và đối chiếu từng dòng với bản gốc là task C03-T06.

## 5. Kiểm tra

**Log thật từ Nginx** (ngày 21/10/2026): chạy Nginx 1.26.3 bản chính thức cho
Windows trên máy phát triển, cấu hình đúng `log_format nids`, rồi gửi các yêu cầu
bằng socket để có từng tình huống. Nginx ghi 13 dòng; parser đọc đủ 13 dòng.

| Tình huống gửi | Nginx ghi | Parser |
|---|---|---|
| GET bình thường | `200`, UA `curl/8.5.0` | Đủ 12 trường |
| 3 yêu cầu trên một kết nối keep-alive | Cùng `conn_id` và cổng, `conn_requests` 1, 2, 3 | Đúng |
| HTTP/1.0 không có User-Agent | UA `"-"` | `user_agent = None` |
| Đường dẫn và UA có `"`, `\`, tiếng Việt | `\x22`, `\x5C`, `\xE1\xBA\xBF` | Giải mã đúng chuỗi gốc |
| Byte TLS gửi tới cổng HTTP | `400`, dòng yêu cầu toàn `\xHH` | Giữ, ghi chú yêu cầu không hợp lệ |
| Yêu cầu dở dang rồi im lặng | `408`, dòng yêu cầu là phần đã nhận `GET /status HTT`, `request_time` 2,001 s | Giữ, ghi chú |
| Lệnh lạ `HELP` | `400` | Giữ, ghi chú |
| Upstream không chạy | `502`, `request_time` 2,029 s | Đúng |
| Client ngắt khi upstream đang chậm | `499`, `request_time` 0,502 s | Đúng |
| Kết nối rồi đóng, không gửi gì | Không ghi dòng nào | — |
| Dòng yêu cầu dài 3 000 byte | `404` | Đúng |

Bản Windows kết thúc dòng bằng CRLF; parser chấp nhận cả LF và CRLF. Trên Kali
và máy chủ dịch vụ Linux sẽ là LF; cần đọc lại log thật của máy chủ dịch vụ khi
lab dựng xong.

**Kiểm thử tự động** (16 ca, tổng 80 ca của dự án): 12 dòng log thật ở trên, dòng
minh họa trong tài liệu 05, IPv6 và cổng `-`, các lý do bỏ qua, hàm giải mã và
tách dòng yêu cầu, file CRLF, file `.gz`, file lẫn dòng hỏng và dòng cuối dở
dang, thời gian giảm, dòng lệnh, cảnh báo sai định dạng.

**Tốc độ:** khoảng 45 000 dòng/giây trên máy phát triển (480 000 dòng trong
10,7 giây), đủ cho log của một lần chạy lab.
