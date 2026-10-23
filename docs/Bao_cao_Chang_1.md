# Báo cáo Chặng 1 — Chốt yêu cầu và khởi tạo dự án

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng (*Machine Learning-Based Network Intrusion Detection Using Network Traffic
Data*)

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 10/10/2026 – 11/10/2026 |
| Trạng thái | Xong 5/5 task |
| Kế hoạch | [Ke_hoach_trien_khai.md](Ke_hoach_trien_khai.md) (12 chặng, 82 task) |
| Chặng sau | [Bao_cao_Chang_2.md](Bao_cao_Chang_2.md) |

## 1. Tóm tắt

Chặng 1 chốt **làm gì** và **dựng chỗ làm việc**: rút đề bài thành bảng yêu
cầu, chốt đầu ra của ba module, tạo kho mã nguồn với cấu trúc thư mục, môi
trường Python, file cấu hình chung và nhật ký quyết định.

Chặng này không có dữ liệu, mô hình hay kết quả thực nghiệm nào.

## 2. Các task

| Task | Nội dung | Trạng thái | Sản phẩm |
|---|---|---|---|
| C01-T01 | Lập bảng yêu cầu bắt buộc và tùy chọn từ đề bài | Xong | [01_yeu_cau.md](01_yeu_cau.md) |
| C01-T02 | Chốt đầu ra ba module | Xong | [02_dau_ra_module.md](02_dau_ra_module.md), `src/nids/scope.py`, `src/nids/alerts.py` |
| C01-T03 | Tạo repository và cấu trúc thư mục | Xong | Kho GitHub, 9 thư mục |
| C01-T04 | Tạo môi trường Python, dependencies và `.gitignore` | Xong | `pyproject.toml`, `requirements.txt`, `requirements-notebook.txt`, `.gitignore` |
| C01-T05 | Tạo README, cấu hình chung và nhật ký quyết định | Xong | `README.md`, `config/default.yaml`, [03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md) |

## 3. Kết quả từng task

### 3.1. C01-T01 — Bảng yêu cầu

Kịch bản triển khai và kiểm thử được rà theo từng mục và tách thành **25 yêu
cầu bắt buộc** (B01–B25) và **6 yêu cầu tùy chọn** (T01–T06). Mỗi yêu cầu ghi
số mục nguồn trong kịch bản. Bắt buộc khi kịch bản dùng từ "phải", "không
được" hoặc mô tả việc hệ thống thực hiện; tùy chọn khi dùng từ "có thể",
"nếu", "khi đủ" hoặc ghi rõ làm sau.

| Nhóm yêu cầu bắt buộc | Mã |
|---|---|
| Thu traffic, flow và cửa sổ đặc trưng | B01, B02 |
| Ba module, cách chạy song song, ghi cảnh báo | B03–B08 |
| Dữ liệu, nhật ký lần chạy, tách tập, đồng nhất huấn luyện và realtime | B09–B12 |
| Mạng lab và năm kịch bản kiểm thử | B13–B18 |
| Lặp lại, chỉ số đánh giá, độ trễ, trình diễn | B19–B22 |
| Sản phẩm bàn giao, an toàn, trung thực kết quả | B23–B25 |

| Mã | Yêu cầu tùy chọn | Điều kiện |
|---|---|---|
| T01 | Mở rộng sang DDoS | Nhiều nguồn phát, ghi nhận kết quả riêng |
| T02 | Chạy DoS với cả SYN và ICMP | Kịch bản cho phép chọn một loại |
| T03 | Đánh giá riêng traffic chưa có trong dữ liệu huấn luyện | Khi thử loại traffic ngoài tập huấn luyện |
| T04 | So sánh Random Forest và Logistic Regression cho botnet | Khi đủ nhãn |
| T05 | Hiển thị đồ thị giao tiếp khi trình diễn | Nếu có |
| T06 | Dashboard | Sau khi các module chạy đúng |

Ngoài phạm vi: dùng mã độc thật, thử nghiệm ngoài mạng lab, tự động chặn tấn
công.

### 3.2. C01-T02 — Đầu ra ba module

| Module | Phương pháp | Nhãn đầu ra | Nhãn sinh cảnh báo |
|---|---|---|---|
| `anomaly` | Gaussian đa biến học từ traffic bình thường | `normal`, `anomaly` (kèm điểm bất thường) | `anomaly` |
| `attack_classification` | Random Forest, so sánh với Logistic Regression | `benign`, `port_scan`, `dos` | `port_scan`, `dos` |
| `botnet_topology` (host) | Đặc trưng beaconing và đồ thị | `normal_host`, `suspect_host` | `suspect_host` |
| `botnet_topology` (topology) | Đặc trưng đồ thị | `centralized`, `p2p`, `none` | `centralized`, `p2p` |

Ba module chạy song song; module anomaly không là cổng lọc cho hai module còn
lại. Kết quả host botnet và kết quả topology được đánh giá riêng. Tên nhãn là
quy ước do nhóm đặt, đang ở trạng thái tạm thời (QĐ-004).

Bản đầu tiên chỉ xuất cảnh báo ra terminal và file CSV; cả ba module dùng chung
11 cột: `module`, `label`, `window_start`, `window_end`, `src_ip`, `dst_ip`,
`score`, `threshold`, `run_id`, `detail`, `created_at` (chi tiết ở
[02_dau_ra_module.md](02_dau_ra_module.md)).

Phần ghi cảnh báo (`src/nids/alerts.py`) đã viết nhưng chưa nối với mô hình
nào. Ví dụ dưới đây là dữ liệu mẫu do chương trình tự sinh để kiểm tra định
dạng, **không phải kết quả phát hiện**:

```
2026-10-11T12:46:28.876Z | [anomaly] | ANOMALY | 192.168.50.20 -> 192.168.50.30 | score=42.7 (ngưỡng 18.3) | run=MAU-DINH-DANG | mẫu định dạng
```

### 3.3. C01-T03 — Repository và cấu trúc thư mục

| Thư mục | Mục đích |
|---|---|
| `config/` | Cấu hình chung (sau này thêm manifest dữ liệu) |
| `docs/` | Kế hoạch, yêu cầu, tài liệu kỹ thuật, nhật ký quyết định, báo cáo |
| `src/nids/` | Mã nguồn |
| `tests/` | Kiểm thử tự động |
| `scripts/` | Script sinh traffic mô phỏng (chưa có) |
| `notebooks/` | Notebook huấn luyện và đánh giá (chưa có) |
| `data/`, `models/`, `output/` | Dữ liệu, mô hình, kết quả chạy; không đưa lên git |

Kho ban đầu tên `attt`, ngày 23/10/2026 đổi sang `ml-nids`; GitHub tự chuyển
hướng link cũ. Kho để chế độ công khai, chỉ người được mời cộng tác mới push
được.

### 3.4. C01-T04 — Môi trường Python

- Python 3.10 trở lên, môi trường ảo `.venv`, cài bằng `pip install -e .`.
- Thư viện chính: numpy, pandas, scikit-learn, scapy, networkx, PyYAML,
  joblib. Nhóm notebook: jupyter, matplotlib.
- `.gitignore` loại trừ môi trường ảo, file tạm của Python, dữ liệu, PCAP, mô
  hình và kết quả chạy.

Đã kiểm tra trên Windows với Python 3.13: tạo môi trường ảo mới, cài đặt thành
công, import được các thư viện chính. **Chưa kiểm tra trên Kali Linux.**

### 3.5. C01-T05 — README, cấu hình và nhật ký quyết định

- `README.md`: giới thiệu, danh sách task, cấu trúc thư mục, cách cài đặt và
  chạy thử, quy ước làm việc.
- `config/default.yaml`: giao diện bắt gói, cửa sổ đặc trưng (10 giây bước 2
  giây; 120 giây bước 10 giây), timeout của flow, địa chỉ 7 node trong lab,
  đường dẫn, cấu hình ghi cảnh báo, random seed. Đọc qua `src/nids/config.py`,
  có kiểm tra giá trị hợp lệ.
- `docs/03_nhat_ky_quyet_dinh.md`: mẫu ghi quyết định và 7 quyết định đầu tiên.

## 4. Quyết định kỹ thuật

| Mã | Quyết định | Trạng thái |
|---|---|---|
| QĐ-001 | Chia hệ thống thành ba module chạy song song | Đã chốt |
| QĐ-002 | Bản đầu tiên chỉ xuất terminal và CSV | Đã chốt |
| QĐ-003 | Một schema cảnh báo chung cho cả ba module | Đã chốt |
| QĐ-004 | Tên nhãn | Tạm thời |
| QĐ-005 | Tách cấu hình khỏi mã nguồn | Đã chốt |
| QĐ-006 | Cửa sổ 10 giây/2 giây và 120 giây/10 giây; timeout flow 60 giây | Tạm thời |
| QĐ-007 | Môi trường Python và thư viện | Đã chốt |

## 5. Kiểm thử

| File | Số ca | Nội dung |
|---|---|---|
| `tests/test_alerts.py` | 8 | Định dạng cảnh báo, xuất terminal và CSV |
| `tests/test_config.py` | 2 | Đọc cấu hình, từ chối cửa sổ sai |

`python -m unittest discover -s tests`: 10/10 ca đạt khi kết thúc chặng.

## 6. Điểm cần lưu ý

1. Timeout nhàn rỗi của flow (60 giây) là giá trị nhóm tự chọn; kịch bản không
   quy định. Sẽ chỉnh trên tập validation.
2. Tên giao diện giám sát `eth0` là giá trị giả định, phải chỉnh theo máy Kali
   thực tế.
3. Nhãn topology `none` cần xem lại khi thu dữ liệu đối chứng.
4. Môi trường mới kiểm tra trên Windows, chưa kiểm tra trên Kali Linux.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Chặng, task | Chặng là một giai đoạn của kế hoạch; task là một việc cụ thể trong chặng, có mã dạng Cxx-Txx |
| Kho mã nguồn (repository), nhánh `main` | Nơi lưu mã và tài liệu trên GitHub kèm lịch sử thay đổi; `main` là dòng phát triển chính |
| Yêu cầu bắt buộc / tùy chọn | Phải làm mới đạt đề bài / làm thêm nếu có điều kiện |
| Module | Một phần độc lập của hệ thống, làm một việc riêng |
| Anomaly, attack classification, botnet/topology | Phát hiện bất thường; phân loại tấn công; phát hiện botnet và hình dạng mạng giao tiếp |
| Gaussian đa biến | Mô hình thống kê mô tả dữ liệu bình thường bằng trung bình và độ phân tán của nhiều đặc trưng; mẫu quá xa bị coi là bất thường |
| Random Forest, Logistic Regression | Hai mô hình phân loại: nhiều cây quyết định bỏ phiếu / tính xác suất từ tổng có trọng số của các đặc trưng |
| Benign, port scan, DoS, DDoS | Bình thường; quét cổng (dò xem máy mở cổng nào); làm máy chủ quá tải từ một nguồn; như DoS nhưng từ nhiều nguồn |
| SYN, ICMP | SYN là gói mở kết nối TCP; ICMP là giao thức của lệnh ping. Hai cách gây DoS |
| Botnet, beaconing | Mạng máy bị nhiễm cùng nghe lệnh; bot định kỳ gọi về máy điều khiển theo chu kỳ đều |
| Topology tập trung / ngang hàng (P2P) | Các bot cùng nói chuyện với một máy điều khiển / các bot nói chuyện trực tiếp với nhau |
| Cổng lọc | Bước bắt buộc phải qua trước; module anomaly không chặn hai module kia |
| Nhãn, nhãn sinh cảnh báo | Kết quả module trả về cho một mẫu; nhãn mà khi đoán ra thì ghi cảnh báo |
| Schema | Danh sách cột cố định và ý nghĩa từng cột của một bảng |
| UTC, ISO 8601 | Giờ chuẩn quốc tế; cách viết ngày giờ chuẩn như `2026-10-11T12:46:28.876Z` |
| Terminal, CSV | Cửa sổ dòng lệnh; file bảng dạng chữ, cột cách nhau bằng dấu phẩy |
| Dashboard | Trang giao diện hiển thị số liệu và cảnh báo trực quan |
| Python, venv, pip, dependencies | Ngôn ngữ của dự án; môi trường ảo riêng của dự án; công cụ cài thư viện; các thư viện dự án cần |
| numpy, pandas, scikit-learn, scapy, networkx, PyYAML, joblib | Thư viện: tính toán mảng số; xử lý bảng; học máy; bắt và đọc gói tin; đồ thị; đọc file YAML; lưu mô hình |
| .gitignore | File liệt kê những gì không đưa lên git |
| YAML, cấu hình | Định dạng file chữ dễ đọc; các tham số chỉnh được mà không sửa mã |
| Cửa sổ, bước | Đoạn thời gian cố định để gom số liệu; khoảng dời cửa sổ mỗi lần |
| Flow, timeout | Tất cả gói của một kết nối giữa hai đầu; khoảng không có gói mới thì coi flow đã kết thúc |
| Random seed | Số khởi đầu cho phép ngẫu nhiên, để chạy lại cho cùng kết quả |
| Validation | Phần dữ liệu dùng để chọn tham số và ngưỡng |
| Kali Linux, node | Bản Linux chuyên kiểm thử bảo mật, là máy giám sát; một máy trong mạng lab |
| Kiểm thử tự động (unittest) | Mã tự chạy chương trình với dữ liệu biết trước và kiểm tra kết quả |
| Nhật ký quyết định (QĐ) | Nơi ghi mỗi lựa chọn kỹ thuật quan trọng cùng lý do |
