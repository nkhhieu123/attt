# Nhật ký quyết định kỹ thuật

Mỗi quyết định ghi một mục, không sửa mục cũ. Khi đổi ý, thêm mục mới và ghi
mục cũ là "Thay bởi QĐ-xxx".

Mẫu:

```
## QĐ-xxx — Tiêu đề
- Ngày: dd/mm/yyyy
- Trạng thái: Đã chốt | Tạm thời | Thay bởi QĐ-xxx
- Bối cảnh:
- Quyết định:
- Hệ quả:
```

## QĐ-001 — Chia hệ thống thành ba module chạy song song
- Ngày: 10/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Kịch bản yêu cầu phát hiện bất thường, phân loại tấn công và phát hiện botnet/topology; Gaussian không được làm cổng lọc.
- Quyết định: Ba module `anomaly`, `attack_classification`, `botnet_topology` nhận cùng luồng đặc trưng và phát cảnh báo độc lập.
- Hệ quả: Một cửa sổ có thể sinh nhiều cảnh báo từ các module khác nhau; việc hợp nhất làm ở bước ghi cảnh báo.

## QĐ-002 — Bản đầu tiên chỉ xuất terminal và CSV
- Ngày: 10/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Cần kiểm chứng các module trước khi đầu tư giao diện.
- Quyết định: Cảnh báo ghi ra terminal và nối vào `output/alerts.csv`. Dashboard là yêu cầu tùy chọn T06.
- Hệ quả: CSV là nguồn dữ liệu để tính chỉ số; dashboard sau này đọc cùng file.

## QĐ-003 — Một schema cảnh báo chung cho cả ba module
- Ngày: 10/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Cần đối chiếu cảnh báo với nhật ký kịch bản và tính độ trễ phát hiện.
- Quyết định: Dùng các cột trong `docs/02_dau_ra_module.md`; có `run_id` để khớp nhật ký và `created_at` để tính độ trễ. Thời gian ghi theo UTC, ISO 8601.
- Hệ quả: Với cảnh báo topology, node trung tâm ghi ở `dst_ip`, `src_ip` để trống.

## QĐ-004 — Tên nhãn
- Ngày: 10/10/2026
- Trạng thái: Tạm thời
- Bối cảnh: Kịch bản nêu các lớp nhưng không quy định tên trong dữ liệu.
- Quyết định: Tên tiếng Anh viết thường: `normal`/`anomaly`; `benign`/`port_scan`/`dos`; `normal_host`/`suspect_host`; `centralized`/`p2p`/`none`.
- Hệ quả: Nhãn của CIC-IDS2017 và CTU-13 phải ánh xạ về các tên này khi chuẩn bị dữ liệu. Nhãn topology `none` cần xem lại khi thu dữ liệu đối chứng.

## QĐ-005 — Tách cấu hình khỏi mã nguồn
- Ngày: 11/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Cửa sổ, địa chỉ lab và đường dẫn thay đổi theo môi trường và được chỉnh trên validation.
- Quyết định: Tham số nằm trong `config/default.yaml`, đọc qua `nids.config.load_config()`. Tên module và tập nhãn là hợp đồng giữa các phần mã nên nằm trong `src/nids/scope.py`.
- Hệ quả: Huấn luyện và realtime phải đọc cùng một file cấu hình (yêu cầu B12).

## QĐ-006 — Tham số cửa sổ và timeout ban đầu
- Ngày: 11/10/2026
- Trạng thái: Tạm thời
- Bối cảnh: Kịch bản cho giá trị cửa sổ ban đầu nhưng không cho giá trị timeout của flow.
- Quyết định: Cửa sổ flow/host 10 giây bước 2 giây; cửa sổ beaconing/đồ thị 120 giây bước 10 giây (theo kịch bản). Timeout nhàn rỗi của flow đặt 60 giây (nhóm tự chọn).
- Hệ quả: Các giá trị này được chỉnh trên tập validation rồi khóa lại trước khi kiểm thử; khi khóa phải thêm mục quyết định mới.

## QĐ-007 — Môi trường Python và thư viện
- Ngày: 11/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Cần một môi trường chạy được trên cả máy phát triển và Kali Linux.
- Quyết định: Python 3.10 trở lên, môi trường ảo `.venv`, cài bằng `pip install -e .`. Thư viện: numpy, pandas, scikit-learn (mô hình), scapy (bắt và đọc gói tin), networkx (đồ thị), PyYAML (cấu hình), joblib (lưu mô hình); nhóm `notebook` gồm jupyter và matplotlib.
- Hệ quả: Dữ liệu, PCAP, mô hình và kết quả chạy không đưa lên git (xem `.gitignore`).

## QĐ-008 — Log dịch vụ là access log của Nginx
- Ngày: 12/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Cần một loại log dịch vụ để đối chiếu với lưu lượng mạng bắt được trên Kali.
- Quyết định: Dùng access log của Nginx trên máy chủ dịch vụ `192.168.50.30`, định dạng riêng `nids` có cổng nguồn, thời điểm tới mili giây và thời gian phục vụ (xem `docs/05_log_dich_vu.md`). Log chỉ dùng để đối chiếu, không là đầu vào của mô hình và không dùng để gán nhãn.
- Hệ quả: Đồng hồ của máy chủ dịch vụ và Kali phải đồng bộ trước mỗi lần chạy. Log mỗi lần chạy lưu ở `data/service_logs/<run_id>/`.

## QĐ-009 — Tập con CIC-IDS2017 cho phân loại
- Ngày: 12/10/2026
- Trạng thái: Tạm thời
- Bối cảnh: Module phân loại có ba lớp `benign`, `port_scan`, `dos` (một nguồn); CIC-IDS2017 có nhiều loại tấn công khác.
- Quyết định: Dùng phiên thứ Tư 05/07/2017 (bốn công cụ DoS, bỏ Heartbleed) và phần port scan của chiều thứ Sáu 07/07/2017 (bỏ DDoS LOIT). Dữ liệu chính là PCAP chạy qua bộ ghép flow của đồ án, nhãn gán theo lịch tấn công; CSV có nhãn dùng để đối chiếu (xem `docs/06_cic_ids2017.md`).
- Hệ quả: Tách train/validation/test theo khối thời gian vì mỗi lớp tấn công chỉ nằm trong một ngày. DoS của CIC-IDS2017 là tầng HTTP, không khớp với SYN/ICMP của lab; nguồn mẫu `dos` cho loại này chưa được quyết định. Chưa tải file nên số liệu phải đối chiếu lại.

## QĐ-010 — Dùng flow hai chiều có nhãn của CTU-13
- Ngày: 12/10/2026
- Trạng thái: Tạm thời
- Bối cảnh: Mỗi scenario CTU-13 phát hành nhiều dạng file với hai kiểu nhãn khác nhau; PCAP đầy đủ của toàn mạng không được công bố.
- Quyết định: Dùng file `.binetflow` trong `detailed-bidirectional-flow-labels/` của cả 13 scenario. Chỉ flow `From-Botnet` là độc hại. Host bot có flow `From-Botnet` trong cửa sổ là `suspect_host`; ba máy bình thường đã xác nhận là `normal_host`; host Background không đưa vào đánh giá (xem `docs/07_ctu13.md`). Không tải các file mẫu mã độc.
- Hệ quả: Đặc trưng của module botnet phải tính được từ bản ghi flow. Chỉ scenario 12 là P2P nên topology ngang hàng phải đánh giá bằng dữ liệu lab. Điểm xuất phát cho việc tách là cách chia của bài báo gốc; scenario làm validation chưa chốt.

## QĐ-011 — Manifest dữ liệu là một file CSV trong config
- Ngày: 14/10/2026
- Trạng thái: Đã chốt
- Bối cảnh: Dữ liệu đến từ ba nguồn với định dạng và cách gán nhãn khác nhau; cần một nơi ghi dữ liệu nào phục vụ bài toán nào.
- Quyết định: Ghi vào `config/data_manifest.csv`, đọc và kiểm tra bằng `nids.manifest.load_manifest()` (xem `docs/08_manifest_du_lieu.md`). Mỗi dòng ghi nguồn gốc thật của dữ liệu; NETRESEC là trang danh mục nên không được ghi là nguồn. Dữ liệu lab ghi theo biến thể kịch bản, từng lần chạy ghi trong nhật ký lần chạy.
- Hệ quả: Khi tải hoặc thu xong dữ liệu phải cập nhật cột `trang_thai`. Nhãn trong manifest phải thuộc tập nhãn của `src/nids/scope.py`.

## QĐ-012 — Dữ liệu tự thu trong lab
- Ngày: 14/10/2026
- Trạng thái: Tạm thời
- Bối cảnh: CIC-IDS2017 không có DoS kiểu SYN/ICMP và thuộc mạng khác; CTU-13 chỉ có một scenario ngang hàng; không dataset nào có đối chứng lành tính.
- Quyết định: Thu 11 biến thể của năm kịch bản (xem `docs/09_du_lieu_lab.md`). DoS dùng SYN; ICMP và DDoS nhiều nguồn là tùy chọn. Mỗi biến thể tối thiểu 1 lần chạy `train`, 1 lần `val`, 3 lần `test`; vai trò ghi trước khi chạy. Mã lần chạy dạng `<mã biến thể>-<vai trò>-<số thứ tự>`.
- Hệ quả: Tối thiểu 55 lần chạy, khoảng 8 giờ thu. Tham số tốc độ quét, ba mức tải DoS và chu kỳ beaconing chưa chốt, phải ghi vào cấu hình trước lần chạy đầu tiên. Các lần chạy `test` thu sau khi mô hình và ngưỡng đã khóa.
