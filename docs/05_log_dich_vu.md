# C02-T02 — Chọn loại log dịch vụ

Loại log được chọn: **access log của web server Nginx** trên máy chủ dịch vụ
`192.168.50.30` (quyết định QĐ-008).

## 1. Lý do chọn

| Tiêu chí | Access log web server |
|---|---|
| Có sẵn trong lab | Máy chủ dịch vụ đã phục vụ HTTP cho traffic bình thường và tác vụ kiểm tra trạng thái định kỳ (B14) |
| Khớp với dữ liệu mạng | Mỗi dòng có IP, cổng nguồn và thời điểm, ghép được với flow |
| Liên quan tới kịch bản | Thấy trực tiếp traffic bình thường; thấy gián tiếp ảnh hưởng của DoS qua thời gian phục vụ và mã lỗi |
| Định dạng | Văn bản một dòng một yêu cầu, tự định nghĩa được trường, dễ phân tích |

Các lựa chọn khác đã cân nhắc:

- Log xác thực SSH (`auth.log`): chỉ hữu ích cho tấn công dò mật khẩu, không
  thuộc ba lớp Benign / Port Scan / DoS của đồ án.
- Log truy vấn DNS: lab không có máy chủ DNS riêng trong bảng địa chỉ.
- Log tường lửa: trùng thông tin với PCAP mà Kali đã bắt.

## 2. Vai trò trong đồ án

Log dịch vụ là **nguồn đối chiếu**, không phải đầu vào của ba module. Ba module
chỉ dùng đặc trưng tính từ lưu lượng mạng, đúng với tên đề tài.

Log dùng cho các việc sau:

1. Kiểm tra nhật ký lần chạy (B10): xác nhận traffic bình thường thực sự được
   sinh ra trong khoảng thời gian đã ghi.
2. Đo ảnh hưởng của DoS (B16): thời gian phục vụ và tỷ lệ lỗi của client hợp lệ
   ở ba mức tải.
3. Phân tích phát hiện sai (B23): tra lại một flow bị cảnh báo nhầm ứng với yêu
   cầu HTTP nào.
4. Phân biệt tác vụ kiểm tra trạng thái định kỳ với beaconing khi xem xét báo
   động giả của module botnet (B14, B17).

Log **không** được dùng để gán nhãn. Nhãn chỉ lấy từ nhật ký lần chạy (B10).

## 3. Định dạng

Định dạng `combined` mặc định của Nginx thiếu ba thứ cần cho việc ghép với
flow: cổng nguồn, thời gian có phần lẻ của giây và thời gian phục vụ. Vì vậy
dùng một định dạng riêng, đặt tên `nids`:

```nginx
log_format nids '$msec $remote_addr $remote_port $server_port '
                '"$request" $status $body_bytes_sent $request_length '
                '$request_time $connection $connection_requests '
                '"$http_user_agent"';

access_log /var/log/nginx/access_nids.log nids;
```

| Thứ tự | Trường | Biến Nginx | Ý nghĩa |
|---|---|---|---|
| 1 | `ts` | `$msec` | Thời điểm ghi log, giây Unix kèm mili giây |
| 2 | `client_ip` | `$remote_addr` | IP của client |
| 3 | `client_port` | `$remote_port` | Cổng nguồn của client |
| 4 | `server_port` | `$server_port` | Cổng nhận yêu cầu |
| 5 | `request` | `$request` | Dòng yêu cầu: phương thức, đường dẫn, phiên bản HTTP |
| 6 | `status` | `$status` | Mã trạng thái HTTP |
| 7 | `body_bytes` | `$body_bytes_sent` | Số byte nội dung trả về, không tính header |
| 8 | `request_bytes` | `$request_length` | Độ dài yêu cầu, gồm dòng yêu cầu, header và nội dung |
| 9 | `request_time` | `$request_time` | Thời gian phục vụ (giây, độ phân giải mili giây) |
| 10 | `conn_id` | `$connection` | Số thứ tự kết nối TCP |
| 11 | `conn_requests` | `$connection_requests` | Số yêu cầu đã phục vụ trên kết nối này |
| 12 | `user_agent` | `$http_user_agent` | Chuỗi User-Agent |

Dòng minh họa định dạng (không phải dữ liệu thực nghiệm):

```
1791793800.123 192.168.50.41 51544 80 "GET /status HTTP/1.1" 200 15 78 0.002 1207 3 "curl/8.5.0"
```

## 4. Ghép với flow

- Khóa ghép: (`client_ip`, `client_port`, `192.168.50.30`, `server_port`, TCP)
  cùng với thời gian.
- Nginx ghi log khi yêu cầu **kết thúc**. Thời điểm bắt đầu yêu cầu xấp xỉ
  `ts - request_time`.
- Một kết nối keep-alive mang nhiều yêu cầu, tức nhiều dòng log ứng với một
  flow. Các dòng cùng `conn_id` thuộc cùng một kết nối.
- `body_bytes` và `request_bytes` là byte tầng ứng dụng, nhỏ hơn số byte của
  flow vì không tính header TCP/IP và các gói điều khiển.
- Đồng hồ của máy chủ dịch vụ và Kali phải được đồng bộ trước mỗi lần chạy;
  độ lệch đo được ghi vào nhật ký lần chạy.

## 5. Giới hạn

Access log chỉ ghi yêu cầu HTTP đã tới tầng ứng dụng, nên không thấy phần lớn
hành vi tấn công trong các kịch bản:

| Kịch bản | Xuất hiện trong access log |
|---|---|
| Traffic bình thường (B14) | Có, đầy đủ |
| Quét cổng (B15) | Hầu như không. SYN scan không hoàn tất kết nối; chỉ kiểu quét dò phiên bản dịch vụ mới để lại dòng log trên cổng web |
| DoS SYN hoặc ICMP (B16) | Không có dòng nào của bên tấn công. Chỉ thấy gián tiếp: `request_time` của client hợp lệ tăng, số yêu cầu hoàn tất giảm |
| Botnet mô phỏng (B17, B18) | Không, trừ khi bot gọi tới máy chủ dịch vụ. Giao tiếp với server điều phối `192.168.50.50` và giữa các bot nằm ngoài log này |

Ngoài ra:

- Log không có yêu cầu bị rớt trước khi Nginx nhận được, nên không dùng log để
  đếm số gói hay số kết nối bị mất.
- Yêu cầu không hoàn chỉnh hoặc bị ngắt được ghi với dòng yêu cầu rỗng và mã
  400, 408 hoặc 499 (499 là mã riêng của Nginx: client đóng kết nối trước).

## 6. Lưu trữ

- Mỗi lần chạy sao chép log về `data/service_logs/<run_id>/access_nids.log`.
  Thư mục `data/` không đưa lên git.
- Xoay vòng log trước mỗi lần chạy để một file chỉ chứa một lần chạy.
- Ghi tên file log vào nhật ký lần chạy cùng với tên file PCAP.

## 7. Việc còn lại

- Cài Nginx và áp dụng `log_format nids` trên máy chủ dịch vụ; kiểm tra bằng
  một yêu cầu thử.
- Viết hàm đọc log thành bảng với 12 cột ở mục 3.
