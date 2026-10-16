# Tổng quan: bộ dữ liệu, mô hình học máy và dữ liệu chuẩn

Tài liệu tóm tắt đồ án dùng dữ liệu gì, mô hình nào và lấy nhãn chuẩn (ground
truth) từ đâu. Chi tiết nằm trong các tài liệu được dẫn ở từng mục.

Đây là kế hoạch đã chốt sau Chặng 2. Chưa có mô hình nào được huấn luyện và
chưa có dữ liệu lab nào được thu.

## 1. Bộ dữ liệu

| Bộ dữ liệu | Dùng cho | Phần được chọn |
|---|---|---|
| **CIC-IDS2017** (Đại học New Brunswick, Canada, thu năm 2017) | Phát hiện bất thường, phân loại tấn công | Thứ Hai: chỉ có traffic bình thường. Thứ Tư: 4 công cụ DoS (slowloris, Slowhttptest, Hulk, GoldenEye). Chiều thứ Sáu: quét cổng bằng Nmap |
| **CTU-13** (Đại học Kỹ thuật Séc, thu năm 2011) | Phát hiện botnet, nhận diện topology | Cả 13 scenario, file flow hai chiều có nhãn (`.binetflow`, khoảng 2,6 GB) |
| **Dữ liệu tự thu trong lab** (mạng 7 máy, bắt gói trên Kali) | Cả ba module và kiểm thử thực tế | 11 biến thể của 5 kịch bản: bình thường, quét cổng, DoS SYN, botnet tập trung, botnet ngang hàng, kèm đối chứng |

Ngoài ra có **access log của Nginx** trên máy chủ dịch vụ, chỉ dùng để đối
chiếu, không đưa vào mô hình.

Chi tiết: [06_cic_ids2017.md](06_cic_ids2017.md),
[07_ctu13.md](07_ctu13.md), [09_du_lieu_lab.md](09_du_lieu_lab.md),
[05_log_dich_vu.md](05_log_dich_vu.md). Danh sách đầy đủ từng file nằm trong
manifest [`config/data_manifest.csv`](../config/data_manifest.csv), mô tả ở
[08_manifest_du_lieu.md](08_manifest_du_lieu.md).

## 2. Mô hình học máy

| Module | Mô hình | Đầu ra |
|---|---|---|
| Phát hiện bất thường (`anomaly`) | **Gaussian đa biến**, chỉ học từ traffic bình thường; ngưỡng chọn trên tập validation | `normal` / `anomaly`, kèm điểm bất thường |
| Phân loại tấn công (`attack_classification`) | **Random Forest** là mô hình chính, **Logistic Regression** để so sánh | `benign` / `port_scan` / `dos` |
| Phát hiện botnet (`botnet_topology`, mức host) | So sánh **ít nhất hai mô hình** (task C08-T05); chưa chọn cụ thể. Yêu cầu tùy chọn T04 gợi ý Random Forest và Logistic Regression | `normal_host` / `suspect_host` |
| Nhận diện topology (`botnet_topology`, mức đồ thị) | Chưa chốt dùng quy tắc hay mô hình học máy (task C08-T07). Đầu vào là đặc trưng đồ thị giao tiếp | `centralized` / `p2p` / `none` |

Ba module chạy song song trên cùng luồng đặc trưng; module bất thường không là
cổng lọc cho hai module còn lại.

Chi tiết: [02_dau_ra_module.md](02_dau_ra_module.md), `src/nids/scope.py`.

## 3. Dữ liệu chuẩn (nhãn ground truth)

| Nguồn | Căn cứ gán nhãn |
|---|---|
| CIC-IDS2017 | **Lịch tấn công công bố**: IP bên tấn công, IP nạn nhân và khung giờ. Flow khớp nhận nhãn tấn công, còn lại là `benign`. File CSV có nhãn của CIC chỉ dùng để đối chiếu, vì đã có nghiên cứu chỉ ra nhãn trong đó có lỗi |
| CTU-13 | **Cột `Label` trong file flow**. Chỉ flow `From-Botnet` là độc hại. Host bot là `suspect_host`, 3 máy bình thường đã xác nhận là `normal_host`. Host `Background` chưa được kiểm chứng nên không đưa vào đánh giá |
| Lab | **Nhật ký lần chạy**: mã lần chạy, thời điểm bắt đầu và kết thúc, IP tham gia, hành vi. Nhật ký ghi độc lập với dự đoán của mô hình |

## 4. Việc còn mở

- CIC-IDS2017 không có DoS kiểu SYN, nên lớp `dos` cần thêm mẫu huấn luyện thu
  trong lab.
- CTU-13 chỉ có một scenario ngang hàng (scenario 12), nên đánh giá `p2p` chủ
  yếu dựa vào dữ liệu lab.
- Chưa tải được dữ liệu CIC-IDS2017 nên tên file và số flow chưa đối chiếu.
- Mô hình cho module botnet và cách nhận diện topology chốt ở Chặng 8.
