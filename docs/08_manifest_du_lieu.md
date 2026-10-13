# C02-T05 — Manifest dữ liệu

Manifest là bảng liệt kê mọi nguồn dữ liệu của đồ án: lấy từ đâu, file nào,
thời gian nào, nhãn gì, dùng cho việc gì. Bảng nằm ở
[`config/data_manifest.csv`](../config/data_manifest.csv) và được đọc bằng
`nids.manifest.load_manifest()` (quyết định QĐ-011).

Manifest chỉ mô tả dữ liệu. Bản thân dữ liệu nằm trong `data/` và không đưa lên
git.

## 1. Các cột

| Cột | Ý nghĩa | Giá trị |
|---|---|---|
| `id` | Mã duy nhất của dòng | Ví dụ `ctu13-s12`, `lab-k3-dos-muc2` |
| `nguon` | Nguồn dữ liệu | `CIC-IDS2017`, `CTU-13`, `Lab` |
| `bai_toan` | Bài toán được phục vụ | `anomaly`, `attack_classification`, `botnet_topology`, `doi_chieu` |
| `file` | Tên file ở nguồn, hoặc đường dẫn mẫu với dữ liệu lab | |
| `dinh_dang` | Định dạng | `pcap`, `csv`, `binetflow`, `log` |
| `thoi_gian` | Ngày thu và thời lượng hoặc khung giờ | |
| `nhan_goc` | Nhãn theo cách gọi của nguồn | |
| `nhan_do_an` | Nhãn tương ứng trong `src/nids/scope.py` | |
| `muc_dich` | Vai trò trong thực nghiệm | `train`, `validation`, `test`, `doi_chieu` |
| `dung_luong` | Dung lượng file, nếu đã biết | |
| `trang_thai` | Mức độ đã kiểm tra | Xem bên dưới |
| `ghi_chu` | Điều cần lưu ý | |

Cột `bai_toan`, `nhan_do_an` và `muc_dich` chứa được nhiều giá trị, ngăn cách
bằng dấu chấm phẩy.

Giá trị của `trang_thai`:

| Giá trị | Ý nghĩa |
|---|---|
| `chua_tai` | Chưa tải. Tên file và nội dung chưa được đối chiếu |
| `da_kiem_tra_may_chu` | Đã thấy file trên máy chủ và ghi dung lượng; chưa tải |
| `da_tai_thu` | Đã tải và kiểm tra cột, nhãn |
| `chua_thu` | Dữ liệu lab chưa thu |

Trình đọc từ chối file khi thiếu cột bắt buộc, trùng `id`, hoặc khi `bai_toan`,
`muc_dich`, `nhan_do_an`, `trang_thai` có giá trị ngoài danh sách.

## 2. Dữ liệu cho từng bài toán

Manifest hiện có 30 dòng: 5 của CIC-IDS2017, 13 của CTU-13, 12 của lab.

### Phát hiện bất thường (`anomaly`)

| Vai trò | Dữ liệu |
|---|---|
| Mẫu bình thường để huấn luyện Gaussian | `cic17-mon-pcap`; các lần chạy `lab-k1-binh-thuong` dành cho huấn luyện |
| Chọn ngưỡng và kiểm thử | Khối thời gian của `cic17-wed-pcap`, `cic17-fri-pcap`; các lần chạy lab kịch bản 2–5 |

Gaussian huấn luyện trên dữ liệu của mạng nào thì chỉ đánh giá trên mạng đó.
Mô hình cho CIC-IDS2017 và mô hình cho lab là hai mô hình riêng.

### Phân loại tấn công (`attack_classification`)

| Lớp | Dữ liệu công khai | Dữ liệu lab |
|---|---|---|
| `benign` | `cic17-wed-pcap`, `cic17-fri-pcap` | `lab-k1-binh-thuong`; phần trước và sau tấn công của kịch bản 2, 3 |
| `port_scan` | `cic17-fri-pcap` | `lab-k2-quet-cham`, `lab-k2-quet-nhanh` |
| `dos` | `cic17-wed-pcap` (DoS tầng HTTP) | `lab-k3-dos-muc1`, `-muc2`, `-muc3` (SYN) |

### Botnet và topology (`botnet_topology`)

| Nhãn | Dữ liệu công khai | Dữ liệu lab |
|---|---|---|
| `suspect_host`, `normal_host` | `ctu13-s01` … `ctu13-s13` | `lab-k4-*`, `lab-k5-*` |
| `centralized` | 10 scenario CTU-13 có kênh điều khiển IRC hoặc HTTP | `lab-k4-co-dinh`, `lab-k4-bien-thien` |
| `p2p` | Chỉ `ctu13-s12` | `lab-k5-p2p` |
| `none` (đối chứng) | Không có | `lab-k1-binh-thuong`, `lab-k4-doi-chung`, `lab-k5-doi-chung` |

Topology của `ctu13-s06` và `ctu13-s08` chưa xác định nên cột `nhan_do_an` của
hai dòng này không có nhãn topology.

### Đối chiếu (`doi_chieu`)

| Dữ liệu | Dùng để |
|---|---|
| `cic17-wed-csv`, `cic17-fri-portscan-csv` | Kiểm tra quy tắc gán nhãn theo lịch tấn công |
| `lab-log-nginx` | Đối chiếu sự kiện với nhật ký lần chạy và lưu lượng |

Dữ liệu đối chiếu không vào mô hình và không dùng để gán nhãn.

## 3. NETRESEC

Kế hoạch nêu NETRESEC như nơi khảo sát nguồn PCAP công khai. NETRESEC là một
**trang danh mục** liệt kê liên kết tới nhiều kho PCAP của các tổ chức khác
nhau. Nó không phải một dataset: các kho được liệt kê không chung định dạng,
không chung cách gán nhãn, và phần lớn không có nhãn.

Vì vậy manifest không có dòng nào ghi nguồn là NETRESEC. Mỗi dòng ghi nguồn
gốc thật của dữ liệu. Nếu sau này lấy thêm một bản thu từ kho được NETRESEC
liệt kê, bản thu đó được thêm vào manifest dưới tên kho gốc, kèm căn cứ gán
nhãn riêng.

## 4. Căn cứ gán nhãn theo nguồn

| Nguồn | Căn cứ gán nhãn |
|---|---|
| CIC-IDS2017 | Lịch tấn công công bố: địa chỉ bên tấn công, nạn nhân và khung giờ ([06_cic_ids2017.md](06_cic_ids2017.md)) |
| CTU-13 | Cột `Label` của file `.binetflow`, quy về host ([07_ctu13.md](07_ctu13.md)) |
| Lab | Nhật ký lần chạy, ghi độc lập với dự đoán ([09_du_lieu_lab.md](09_du_lieu_lab.md)) |

## 5. Cập nhật manifest

- Sửa trực tiếp file CSV, rồi chạy `python -m unittest discover -s tests`.
- Khi tải xong một file: đổi `trang_thai`, điền `dung_luong`, sửa tên file nếu
  khác với tên đang ghi.
- Dữ liệu lab ghi theo **biến thể kịch bản**, không theo từng lần chạy. Từng
  lần chạy được ghi trong nhật ký lần chạy ở `data/run_logs/`.
- Cột `muc_dich` của CIC-IDS2017 và lab ghi `train;validation;test` vì việc
  chia được thực hiện bên trong nguồn (theo khối thời gian hoặc theo lần chạy)
  và chốt ở chặng 5.
