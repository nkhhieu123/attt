# Bước 1 — Chốt phạm vi cần hoàn thành

Đề tài: **Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng mạng**

Tài liệu này chốt những gì đồ án phải làm, đầu ra của từng phần và những gì
chưa làm ở bản đầu tiên. Các hằng số tương ứng nằm trong `src/nids/scope.py`.

## 1. Ba phần của đồ án

| Phần | Nội dung | Phương pháp | Đầu ra |
|---|---|---|---|
| Phát hiện bất thường | Mô hình Gaussian học từ traffic bình thường | Gaussian đa biến | Bình thường/bất thường và điểm bất thường |
| Phân loại | Phân biệt Benign, Port Scan, DoS | Random Forest, so sánh với Logistic Regression | Nhãn dự đoán |
| Botnet | Phân tích giao tiếp và đặc trưng đồ thị | Đặc trưng beaconing/đồ thị; Random Forest và Logistic Regression khi đủ nhãn | Host nghi vấn, cấu trúc tập trung/ngang hàng |

Ba phần chạy song song trên cùng luồng đặc trưng. Phần Gaussian **không** là
cổng lọc bắt buộc cho hai phần còn lại.

## 2. Tập nhãn đầu ra

| Module (`module`) | Nhãn (`label`) | Nhãn sinh cảnh báo |
|---|---|---|
| `anomaly` | `normal`, `anomaly` | `anomaly` |
| `classifier` | `benign`, `port_scan`, `dos` | `port_scan`, `dos` |
| `botnet` (host) | `normal_host`, `suspect_host` | `suspect_host` |
| `botnet` (topology) | `centralized`, `p2p`, `none` | `centralized`, `p2p` |

- Kết quả topology được báo cáo riêng với kết quả phát hiện host botnet.
- Cảnh báo botnet thể hiện mức nghi vấn, không khẳng định có mã độc.
- DoS trong phạm vi này là DoS từ **một nguồn**; DDoS là phần mở rộng, nếu làm
  phải ghi nhận kết quả riêng.

## 3. Đầu ra của bản đầu tiên

Bản đầu tiên chỉ xuất cảnh báo ra **terminal** và **file CSV**
(`output/alerts.csv`). Dashboard làm sau khi các module chạy đúng.

Mọi module dùng chung một schema cảnh báo (`src/nids/alerts.py`):

| Cột | Ý nghĩa |
|---|---|
| `module` | `anomaly`, `classifier` hoặc `botnet` |
| `label` | Nhãn dự đoán theo bảng ở mục 2 |
| `window_start`, `window_end` | Cửa sổ quan sát (UTC, ISO 8601) |
| `src_ip` | Host nguồn / host nghi vấn |
| `dst_ip` | Host đích / node trung tâm |
| `score` | Điểm bất thường hoặc xác suất của mô hình |
| `threshold` | Ngưỡng quyết định (nếu có) |
| `run_id` | Mã lần chạy, khớp với nhật ký kịch bản |
| `detail` | Ghi chú thêm |
| `created_at` | Thời điểm phát cảnh báo, dùng để tính độ trễ phát hiện |

Dạng một dòng trên terminal:

```
<created_at> | [module] | LABEL | src -> dst | score=... (ngưỡng ...) | run=... | detail
```

## 4. Tham số ban đầu

| Tham số | Giá trị |
|---|---|
| Cửa sổ đặc trưng flow/host | 10 giây, cập nhật mỗi 2 giây |
| Cửa sổ đặc trưng beaconing/đồ thị | 120 giây, cập nhật mỗi 10 giây |
| Mạng lab | `192.168.50.0/24`, cô lập |

Các giá trị cửa sổ được điều chỉnh trên tập validation rồi giữ cố định khi
kiểm thử.

## 5. Ngoài phạm vi bản đầu tiên

- Dashboard/giao diện web.
- DDoS nhiều nguồn.
- Mã độc thật: giao tiếp botnet chỉ mô phỏng bằng thông điệp vô hại.
- Tự động chặn hoặc phản ứng với tấn công (hệ thống chỉ phát hiện và ghi cảnh báo).
- Traffic ngoài mạng lab cô lập.

## 6. Tiêu chí hoàn thành Bước 1

- [x] Thống nhất ba phần, phương pháp và đầu ra của từng phần.
- [x] Chốt tập nhãn của từng module.
- [x] Chốt kênh xuất của bản đầu tiên (terminal + CSV) và schema cảnh báo.
- [x] Có mã nguồn ghi cảnh báo theo schema, kèm kiểm thử.
- [x] Liệt kê phần chưa làm ở bản đầu tiên.
