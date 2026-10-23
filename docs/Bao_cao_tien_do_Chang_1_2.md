# Báo cáo tiến độ đồ án — Chặng 1 và Chặng 2

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/attt (nhánh `main`) |
| Ngày báo cáo | 15/10/2026 |
| Chặng đã làm | Chặng 1 — Chốt yêu cầu và khởi tạo dự án; Chặng 2 — Khảo sát dữ liệu và định dạng |
| Trạng thái | Chặng 1: xong 5/5 task. Chặng 2: xong 6/6 task. Chặng 3–12 chưa bắt đầu |
| Kế hoạch | [Ke_hoach_trien_khai.md](Ke_hoach_trien_khai.md) (12 chặng, 82 task) |

## 1. Tóm tắt

Đã hoàn thành 11 task của hai chặng đầu.

- **Chặng 1** chốt phạm vi đồ án: bảng yêu cầu, đầu ra của ba module, cấu trúc
  kho mã nguồn, môi trường Python, cấu hình chung và nhật ký quyết định.
- **Chặng 2** chốt dữ liệu: định dạng PCAP, loại log dịch vụ, tập con
  CIC-IDS2017, kết quả kiểm tra CTU-13, manifest dữ liệu cho từng bài toán và
  danh sách dữ liệu phải tự thu trong lab.

Chưa có mô hình nào được huấn luyện, chưa có lần thu nào trong lab và chưa tải
dữ liệu CIC-IDS2017. Báo cáo này không chứa kết quả thực nghiệm hay chỉ số
đánh giá.

## 2. Tình trạng các task

### Chặng 1 — Chốt yêu cầu và khởi tạo dự án

| Task | Nội dung | Trạng thái | Sản phẩm |
|---|---|---|---|
| C01-T01 | Lập bảng yêu cầu bắt buộc và tùy chọn từ đề bài | Xong | [01_yeu_cau.md](01_yeu_cau.md) |
| C01-T02 | Chốt đầu ra ba module | Xong | [02_dau_ra_module.md](02_dau_ra_module.md), `src/nids/scope.py`, `src/nids/alerts.py` |
| C01-T03 | Tạo repository và cấu trúc thư mục | Xong | Kho GitHub, 9 thư mục |
| C01-T04 | Tạo môi trường Python, dependencies và `.gitignore` | Xong | `pyproject.toml`, `requirements.txt`, `requirements-notebook.txt`, `.gitignore` |
| C01-T05 | Tạo README, cấu hình chung và nhật ký quyết định | Xong | `README.md`, `config/default.yaml`, [03_nhat_ky_quyet_dinh.md](03_nhat_ky_quyet_dinh.md) |

### Chặng 2 — Khảo sát dữ liệu và định dạng

| Task | Nội dung | Trạng thái | Sản phẩm |
|---|---|---|---|
| C02-T01 | Mô tả Global Header, Packet Header, Packet Data của PCAP; phân biệt với PCAPNG | Xong | [04_dinh_dang_pcap.md](04_dinh_dang_pcap.md) |
| C02-T02 | Chọn một loại log dịch vụ | Xong | [05_log_dich_vu.md](05_log_dich_vu.md) |
| C02-T03 | Chọn tập con CIC-IDS2017 cho phân loại | Xong, số liệu chưa đối chiếu | [06_cic_ids2017.md](06_cic_ids2017.md) |
| C02-T04 | Kiểm tra các scenario CTU-13, file khả dụng và ý nghĩa nhãn | Xong | [07_ctu13.md](07_ctu13.md) |
| C02-T05 | Tạo manifest: nguồn, file, thời gian, nhãn, mục đích | Xong | `config/data_manifest.csv`, `src/nids/manifest.py`, [08_manifest_du_lieu.md](08_manifest_du_lieu.md) |
| C02-T06 | Chốt dữ liệu còn phải tự thu trong lab | Xong | [09_du_lieu_lab.md](09_du_lieu_lab.md) |

## 3. Chặng 1 — Chốt yêu cầu và khởi tạo dự án

### 3.1. C01-T01 — Bảng yêu cầu

Kịch bản triển khai và kiểm thử được rà theo từng mục và tách thành 25 yêu cầu
bắt buộc (B01–B25) và 6 yêu cầu tùy chọn hoặc có điều kiện (T01–T06). Mỗi yêu
cầu ghi số mục nguồn trong kịch bản. Bắt buộc khi kịch bản dùng từ "phải",
"không được" hoặc mô tả việc hệ thống thực hiện; tùy chọn khi dùng từ "có
thể", "nếu", "khi đủ" hoặc ghi rõ làm sau.

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

Bản đầu tiên chỉ xuất cảnh báo ra terminal và file CSV, cả ba module dùng chung
một định dạng:

| Cột | Ý nghĩa |
|---|---|
| `module` | `anomaly`, `attack_classification` hoặc `botnet_topology` |
| `label` | Nhãn dự đoán theo bảng trên |
| `window_start`, `window_end` | Cửa sổ quan sát (UTC, ISO 8601) |
| `src_ip` | Host nguồn hoặc host nghi vấn |
| `dst_ip` | Host đích hoặc node trung tâm |
| `score` | Điểm bất thường hoặc xác suất của mô hình |
| `threshold` | Ngưỡng quyết định (nếu có) |
| `run_id` | Mã lần chạy, khớp với nhật ký kịch bản để gán nhãn |
| `detail` | Ghi chú thêm |
| `created_at` | Thời điểm phát cảnh báo, dùng để tính độ trễ phát hiện |

Phần ghi cảnh báo (`src/nids/alerts.py`) đã viết nhưng chưa nối với mô hình
nào. Ví dụ dưới đây là dữ liệu mẫu do chương trình tự sinh để kiểm tra định
dạng, không phải kết quả phát hiện:

```
2026-10-11T12:46:28.876Z | [anomaly] | ANOMALY | 192.168.50.20 -> 192.168.50.30 | score=42.7 (ngưỡng 18.3) | run=MAU-DINH-DANG | mẫu định dạng
2026-10-11T12:46:28.876Z | [attack_classification] | PORT_SCAN | 192.168.50.20 -> 192.168.50.30 | score=0.97 | run=MAU-DINH-DANG | mẫu định dạng
```

### 3.3. C01-T03 — Repository và cấu trúc thư mục

| Thư mục | Mục đích | Hiện có |
|---|---|---|
| `config/` | Cấu hình chung, manifest dữ liệu | `default.yaml`, `data_manifest.csv` |
| `docs/` | Kế hoạch, yêu cầu, tài liệu kỹ thuật, nhật ký quyết định, báo cáo | 11 file |
| `src/nids/` | Mã nguồn | `scope.py`, `config.py`, `alerts.py`, `manifest.py` |
| `tests/` | Kiểm thử | 3 file, 15 ca |
| `scripts/` | Script đọc PCAP, sinh traffic mô phỏng | Trống |
| `notebooks/` | Notebook huấn luyện và đánh giá | Trống |
| `data/` | Dataset, PCAP, nhật ký lần chạy | Trống, không đưa lên git |
| `models/` | Mô hình đã huấn luyện | Trống, không đưa lên git |
| `output/` | File cảnh báo và kết quả chạy | Trống, không đưa lên git |

### 3.4. C01-T04 — Môi trường Python

- Python 3.10 trở lên, môi trường ảo `.venv`, cài bằng `pip install -e .`.
- Thư viện chính: numpy, pandas, scikit-learn, scapy, networkx, PyYAML,
  joblib. Nhóm notebook: jupyter, matplotlib.
- `.gitignore` loại trừ môi trường ảo, file tạm của Python, dữ liệu, PCAP, mô
  hình và kết quả chạy.

Đã kiểm tra trên Windows với Python 3.13: tạo môi trường ảo mới, cài đặt thành
công, import được các thư viện chính. Chưa kiểm tra trên Kali Linux và chưa cài
thử nhóm notebook.

### 3.5. C01-T05 — README, cấu hình và nhật ký quyết định

- `README.md`: giới thiệu, danh sách task, cấu trúc thư mục, cách cài đặt và
  chạy thử, quy ước làm việc.
- `config/default.yaml`: giao diện bắt gói, cửa sổ đặc trưng, timeout của flow,
  địa chỉ 7 node trong lab, đường dẫn, cấu hình ghi cảnh báo, random seed. Đọc
  qua `src/nids/config.py`, có kiểm tra giá trị hợp lệ.
- `docs/03_nhat_ky_quyet_dinh.md`: mẫu ghi quyết định; Chặng 1 ghi 7 quyết định
  QĐ-001 đến QĐ-007 (xem mục 5).

## 4. Chặng 2 — Khảo sát dữ liệu và định dạng

### 4.1. C02-T01 — Định dạng PCAP và PCAPNG

Tài liệu mô tả ba phần của file PCAP:

| Phần | Kích thước | Nội dung chính |
|---|---|---|
| Global Header | 24 byte, một lần ở đầu file | `magic_number` (thứ tự byte, micro/nano giây), phiên bản 2.4, `snaplen`, kiểu tầng liên kết |
| Packet Header | 16 byte, trước mỗi gói | `ts_sec`, `ts_usec`, `incl_len` (byte đã lưu), `orig_len` (byte trên đường truyền) |
| Packet Data | `incl_len` byte | Gói tin tính từ header tầng liên kết, không đệm |

Tài liệu có một ví dụ đọc từng byte của file PCAP 82 byte chứa một gói ARP
giữa hai máy lab, và bảng so sánh PCAP với PCAPNG theo 15 tiêu chí. Khác biệt
chính: PCAPNG là dãy block có kiểu và độ dài, chứa được nhiều giao diện với
kiểu liên kết khác nhau, có chú thích và thống kê mất gói; PCAP chỉ có một
header cố định và một kiểu liên kết cho cả file.

Kết luận dùng cho các chặng sau:

- Đặc trưng về dung lượng tính từ `orig_len`, không từ `incl_len`.
- Nhận biết định dạng bằng 4 byte đầu file, không theo phần mở rộng.
- File PCAP không chứa số gói bị mất; số này lấy từ thống kê của tcpdump khi
  dừng bắt gói.

### 4.2. C02-T02 — Log dịch vụ

Chọn **access log của Nginx** trên máy chủ dịch vụ `192.168.50.30`, dùng định
dạng riêng `nids` gồm 12 trường. Định dạng này thêm vào định dạng mặc định ba
thứ cần để ghép với flow: cổng nguồn của client, thời điểm tới mili giây và
thời gian phục vụ.

Log chỉ dùng để **đối chiếu**: kiểm tra nhật ký lần chạy, đo ảnh hưởng của DoS
lên client hợp lệ, phân tích phát hiện sai. Log không là đầu vào của mô hình và
không dùng để gán nhãn. Giới hạn đã ghi rõ: SYN scan và DoS SYN không để lại
dòng nào trong access log.

### 4.3. C02-T03 — Tập con CIC-IDS2017

| Nhãn đồ án | Nhãn CIC-IDS2017 | Phiên thu |
|---|---|---|
| `dos` | DoS slowloris, Slowhttptest, Hulk, GoldenEye | Thứ Tư 05/07/2017, 09:47–11:23 |
| `port_scan` | PortScan (27 lượt Nmap, tường lửa bật và tắt) | Thứ Sáu 07/07/2017, 13:55–15:29 |
| `benign` | BENIGN | Cùng hai phiên |

Loại bỏ Heartbleed, DDoS LOIT (ba nguồn phát, trong khi lớp `dos` là một
nguồn), Botnet ARES và dữ liệu thứ Ba, thứ Năm. Thứ Hai (chỉ có traffic bình
thường) dành cho module anomaly.

Dữ liệu huấn luyện chính là **PCAP** của hai phiên, chạy qua bộ tính đặc trưng
của đồ án và gán nhãn theo lịch tấn công công bố. CSV có nhãn của CIC chỉ dùng
để đối chiếu. Lý do: yêu cầu B12 đòi huấn luyện và realtime dùng cùng cách tính
đặc trưng, và các nghiên cứu sau này đã chỉ ra lỗi ghép flow và nhãn trong CSV
gốc. Train/validation/test được tách theo khối thời gian vì mỗi lớp tấn công
chỉ nằm trong một ngày.

**Hạn chế về độ tin cậy:** trang tải dữ liệu yêu cầu đăng ký nên chưa tải file
nào. Lịch tấn công và địa chỉ IP lấy từ trang mô tả chính thức; tên file và số
flow từng nhãn chưa được đối chiếu với file thật.

### 4.4. C02-T04 — CTU-13

Đã kiểm tra trực tiếp máy chủ phát hành dataset ngày 12/10/2026:

- Cả 13 thư mục scenario đều truy cập được. Ghi lại file, dung lượng, thời
  lượng, số bot và địa chỉ host của từng scenario.
- PCAP đầy đủ của toàn mạng **không được công bố**. Có sẵn: flow hai chiều có
  nhãn (`.binetflow`, tổng khoảng 2,6 GB), PCAP của toàn mạng đã cắt còn phần
  header (khoảng 10,4 GB), PCAP chỉ có traffic của bot.
- Đã tải hai file flow của scenario 11 và 12, xác nhận 15 cột và đếm nhãn:
  scenario 11 có 107 251 flow (8 164 flow botnet), scenario 12 có 325 471 flow
  (2 168 flow botnet).

Ý nghĩa nhãn: chỉ flow `From-Botnet` là độc hại. `To-Botnet` và `To-Normal`
không được coi là độc hại; `Background` là traffic chưa kiểm chứng của mạng
trường. Quy về nhãn đồ án: host bot có flow `From-Botnet` trong cửa sổ là
`suspect_host`, ba máy bình thường đã xác nhận là `normal_host`, host
Background không đưa vào đánh giá.

Không tải các file mẫu mã độc có trong thư mục dataset (yêu cầu B24).

### 4.5. C02-T05 — Manifest dữ liệu

`config/data_manifest.csv` có 30 dòng, mỗi dòng ghi nguồn, file, thời gian,
nhãn gốc, nhãn đồ án, mục đích (`train`, `validation`, `test`, `doi_chieu`),
dung lượng và mức độ đã kiểm tra.

| Nguồn | Số dòng | Trạng thái |
|---|---|---|
| CIC-IDS2017 | 5 | Chưa tải |
| CTU-13 | 13 | 11 đã kiểm tra trên máy chủ, 2 đã tải thử |
| Lab | 12 | Chưa thu |

| Bài toán | Dữ liệu |
|---|---|
| `anomaly` | CIC-IDS2017 thứ Hai (huấn luyện), thứ Tư và thứ Sáu (ngưỡng, kiểm thử); lab kịch bản 1–5 |
| `attack_classification` | CIC-IDS2017 thứ Tư và thứ Sáu; lab kịch bản 1, 2, 3 |
| `botnet_topology` | CTU-13 cả 13 scenario; lab kịch bản 4, 5 và hai đối chứng |
| Đối chiếu | CSV có nhãn của CIC-IDS2017; access log Nginx |

`src/nids/manifest.py` đọc manifest và từ chối file khi trùng mã, thiếu cột
bắt buộc, hoặc nhãn không thuộc tập nhãn của đồ án.

NETRESEC là trang danh mục liên kết tới nhiều kho PCAP khác nhau, không phải
một dataset có nhãn thống nhất. Vì vậy manifest không có dòng nào ghi nguồn là
NETRESEC; mỗi dòng ghi nguồn gốc thật của dữ liệu. Đây là tiêu chí nghiệm thu
của Chặng 2.

### 4.6. C02-T06 — Dữ liệu tự thu trong lab

| Thiếu hụt của dữ liệu công khai | Dữ liệu lab bù vào |
|---|---|
| Traffic bình thường của CIC-IDS2017 thuộc mạng khác | Kịch bản 1 |
| CIC-IDS2017 không có DoS kiểu SYN hoặc ICMP | Kịch bản 3, gồm cả lần chạy để huấn luyện |
| CTU-13 chỉ có một scenario ngang hàng với 3 bot | Kịch bản 5 |
| Flow kênh điều khiển trong CTU-13 rất ít, chu kỳ không kiểm soát được | Kịch bản 4 |
| Không có đối chứng lành tính | Hai kịch bản đối chứng |
| Độ trễ, mất gói, CPU, RAM chỉ đo được khi chạy thật | Mọi lần chạy kiểm thử |

Đã chốt 11 biến thể của năm kịch bản: bình thường; quét chậm, quét nhanh; DoS
ba mức tải; beaconing chu kỳ cố định, chu kỳ biến thiên và đối chứng; ngang
hàng và đối chứng. DoS dùng kiểu **SYN**.

Mỗi biến thể tối thiểu 1 lần chạy huấn luyện, 1 lần validation và 3 lần kiểm
thử, với vai trò ghi trước khi chạy. Tổng tối thiểu **55 lần chạy, khoảng 8
giờ thu**. Mỗi lần chạy sinh PCAP, nhật ký lần chạy (căn cứ gán nhãn) và access
log.

## 5. Nhật ký quyết định

| Mã | Quyết định | Chặng | Trạng thái |
|---|---|---|---|
| QĐ-001 | Chia hệ thống thành ba module chạy song song | 1 | Đã chốt |
| QĐ-002 | Bản đầu tiên chỉ xuất terminal và CSV | 1 | Đã chốt |
| QĐ-003 | Một schema cảnh báo chung cho cả ba module | 1 | Đã chốt |
| QĐ-004 | Tên nhãn | 1 | Tạm thời |
| QĐ-005 | Tách cấu hình khỏi mã nguồn | 1 | Đã chốt |
| QĐ-006 | Cửa sổ 10 giây/2 giây và 120 giây/10 giây; timeout flow 60 giây | 1 | Tạm thời |
| QĐ-007 | Môi trường Python và thư viện | 1 | Đã chốt |
| QĐ-008 | Log dịch vụ là access log của Nginx | 2 | Đã chốt |
| QĐ-009 | Tập con CIC-IDS2017 cho phân loại | 2 | Tạm thời |
| QĐ-010 | Dùng flow hai chiều có nhãn của CTU-13 | 2 | Tạm thời |
| QĐ-011 | Manifest dữ liệu là một file CSV trong `config/` | 2 | Đã chốt |
| QĐ-012 | Dữ liệu tự thu trong lab | 2 | Tạm thời |

## 6. Kiểm thử

`python -m unittest discover -s tests`: 15/15 ca đạt.

| File | Số ca | Nội dung |
|---|---|---|
| `tests/test_alerts.py` | 8 | Định dạng cảnh báo, xuất terminal và CSV |
| `tests/test_config.py` | 2 | Đọc cấu hình, từ chối cửa sổ sai |
| `tests/test_manifest.py` | 5 | Mỗi module có dữ liệu, đủ 13 scenario CTU-13, từ chối nhãn lạ và mã trùng |

## 7. Điểm cần lưu ý

1. **Loại DoS không khớp giữa CIC-IDS2017 và lab.** CIC-IDS2017 chỉ có DoS tầng
   HTTP, lab dùng SYN. Lớp `dos` cho kiểu SYN phải lấy mẫu huấn luyện từ các lần
   chạy lab.
2. **Topology ngang hàng thiếu dữ liệu công khai.** CTU-13 chỉ có scenario 12,
   nên đánh giá `p2p` chủ yếu dựa vào lab.
3. **Số liệu CIC-IDS2017 chưa đối chiếu** vì chưa tải được file.
4. **Cách chia train/test của CTU-13** đang theo bài báo gốc và ở trạng thái
   tạm thời.
5. **Tham số chưa chốt:** tốc độ Nmap, ba mức tải DoS, chu kỳ beaconing, số
   peer. Phải ghi vào cấu hình trước lần thu đầu tiên.
6. Timeout nhàn rỗi của flow (60 giây) là giá trị nhóm tự chọn; tên giao diện
   giám sát `eth0` là giá trị giả định, phải chỉnh theo máy Kali thực tế.
7. Nhãn topology `none` cần xem lại khi thu dữ liệu đối chứng.
8. Môi trường mới kiểm tra trên Windows, chưa kiểm tra trên Kali Linux.

## 8. Việc tiếp theo

**Chặng 3 — Chuyển PCAP và log thành dữ liệu có cấu trúc:**

| Task | Nội dung |
|---|---|
| C03-T01 | Viết bộ đọc PCAP theo từng packet |
| C03-T02 | Trích xuất timestamp, IP, giao thức, độ dài |
| C03-T03 | Trích xuất port và cờ TCP khi tồn tại |
| C03-T04 | Xử lý packet không hỗ trợ, lỗi và thống kê bỏ qua |
| C03-T05 | Viết parser cho log dịch vụ đã chọn |
| C03-T06 | Xuất dữ liệu log thành bảng; đối chiếu một số dòng với bản gốc |
| C03-T07 | Đối chiếu kết quả đọc packet với Wireshark |

Song song với Chặng 3:

- Đăng ký và tải bốn file CIC-IDS2017; cập nhật manifest.
- Tải 11 file `.binetflow` còn lại của CTU-13.
- Dựng mạng lab, cài Nginx với định dạng log `nids`, kiểm tra mirror thấy cả
  hai chiều.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Chặng, task | Chặng là một giai đoạn của kế hoạch; task là một việc cụ thể trong chặng |
| Kho mã nguồn (repository) | Nơi lưu mã và tài liệu của dự án trên GitHub, kèm lịch sử thay đổi |
| Nhánh `main` | Dòng phát triển chính của kho mã |
| Module | Một phần độc lập của hệ thống; dự án có ba module phát hiện |
| Gaussian đa biến, Random Forest, Logistic Regression | Ba mô hình học máy: phát hiện bất thường; phân loại bằng nhiều cây quyết định; phân loại bằng xác suất |
| Beaconing | Bot định kỳ gọi về máy điều khiển theo chu kỳ đều |
| Schema | Danh sách cột cố định và ý nghĩa từng cột |
| UTC, ISO 8601 | Giờ chuẩn quốc tế / cách viết ngày giờ chuẩn như `2026-10-11T12:46:28Z` |
| Dependencies | Các thư viện mà dự án cần cài |
| .gitignore | File liệt kê những gì không đưa lên git (dữ liệu, mô hình, file tạm) |
| Random seed | Số khởi đầu cho phép ngẫu nhiên, để chạy lại cho cùng kết quả |
| PCAP, PCAPNG | Hai định dạng file lưu gói tin bắt được |
| snaplen, incl_len, orig_len | Số byte tối đa lưu mỗi gói / số byte đã lưu / độ dài thật của gói |
| Access log, Nginx | Log của máy chủ web Nginx, một dòng một yêu cầu |
| NAT | Bộ chuyển địa chỉ trên tường lửa, làm địa chỉ nguồn nhìn thấy khác địa chỉ thật |
| Binetflow | File flow hai chiều có nhãn của CTU-13 |
| Background | Traffic chưa kiểm chứng của mạng trường trong CTU-13 |
| Manifest | Bảng liệt kê mọi nguồn dữ liệu và cách dùng |
| NETRESEC | Trang web liệt kê liên kết tới nhiều kho PCAP; không phải một bộ dữ liệu |
| Mirror | Sao chép traffic của switch sang máy giám sát |
| Train / validation / test | Dữ liệu để học / để chọn tham số và ngưỡng / để đánh giá cuối |
| Ca kiểm thử | Một kiểm tra tự động của chương trình |
