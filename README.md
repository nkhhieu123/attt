# attt

Đồ án: **Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng mạng**.

Hệ thống giám sát chạy trên Kali Linux trong mạng lab cô lập, gồm ba module:

| Module | Phương pháp | Đầu ra |
|---|---|---|
| Anomaly | Gaussian đa biến học từ traffic bình thường | Bình thường/bất thường và điểm bất thường |
| Attack classification | Random Forest, so sánh với Logistic Regression | Benign, Port Scan, DoS |
| Botnet/topology | Đặc trưng beaconing và đồ thị giao tiếp | Host nghi vấn, cấu trúc tập trung/ngang hàng |

Bản đầu tiên chỉ xuất cảnh báo ra terminal và file CSV; dashboard làm sau.

## Tiến độ

### Chặng 1 — Chốt yêu cầu và khởi tạo dự án

- [x] C01-T01: Lập bảng yêu cầu bắt buộc và tùy chọn từ đề bài — [docs/01_yeu_cau.md](docs/01_yeu_cau.md)
- [x] C01-T02: Chốt đầu ra ba module: anomaly, attack classification, botnet/topology — [docs/02_dau_ra_module.md](docs/02_dau_ra_module.md), `src/nids/scope.py`, `src/nids/alerts.py`
- [x] C01-T03: Tạo repository và cấu trúc thư mục — xem mục Cấu trúc
- [x] C01-T04: Tạo môi trường Python, dependencies và .gitignore — `pyproject.toml`, `requirements.txt`, `.gitignore`
- [x] C01-T05: Tạo README, cấu hình chung và nhật ký quyết định kỹ thuật — `config/default.yaml`, [docs/03_nhat_ky_quyet_dinh.md](docs/03_nhat_ky_quyet_dinh.md)

Báo cáo: [docs/Bao_cao_tien_do_Chang_1.docx](docs/Bao_cao_tien_do_Chang_1.docx)

### Chặng 2

- [x] C02-T01: Mô tả Global Header, Packet Header, Packet Data của PCAP; phân biệt với PCAPNG — [docs/04_dinh_dang_pcap.md](docs/04_dinh_dang_pcap.md)
- [x] C02-T02: Chọn một loại log dịch vụ: access log của Nginx — [docs/05_log_dich_vu.md](docs/05_log_dich_vu.md)
- [x] C02-T03: Chọn tập con CIC-IDS2017 cho phân loại — [docs/06_cic_ids2017.md](docs/06_cic_ids2017.md)
- [x] C02-T04: Kiểm tra các scenario CTU-13, file khả dụng và ý nghĩa nhãn — [docs/07_ctu13.md](docs/07_ctu13.md)

## Cấu trúc

```
config/default.yaml   Cấu hình chung: cửa sổ, timeout, địa chỉ lab, đường dẫn
docs/                 Yêu cầu, đầu ra module, nhật ký quyết định, báo cáo
src/nids/
  scope.py            Tên module và tập nhãn
  config.py           Đọc cấu hình
  alerts.py           Schema cảnh báo, xuất terminal + CSV
tests/                Kiểm thử
scripts/              Script đọc PCAP, sinh traffic mô phỏng (chưa có)
notebooks/            Notebook huấn luyện và đánh giá (chưa có)
data/                 Dataset, PCAP, nhật ký lần chạy (không đưa lên git)
models/               Mô hình đã huấn luyện (không đưa lên git)
output/               File cảnh báo và kết quả chạy (không đưa lên git)
```

## Cài đặt

Yêu cầu Python 3.10 trở lên.

Linux / Kali:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

Thêm thư viện cho notebook: `pip install -e ".[notebook]"`.
Nếu không dùng `pyproject.toml`, có thể cài bằng `pip install -r requirements.txt`
rồi đặt `PYTHONPATH=src`.

## Chạy thử

```bash
# Kiểm thử
python -m unittest discover -s tests

# Xuất cảnh báo mẫu để kiểm tra định dạng (không phải kết quả thực nghiệm)
python -m nids.alerts
```

## Quy ước

- Tham số chỉnh trong `config/default.yaml`, không viết cứng trong mã.
- Mỗi quyết định kỹ thuật thêm một mục vào `docs/03_nhat_ky_quyet_dinh.md`.
- Chỉ thử nghiệm trong mạng lab cô lập; giao tiếp botnet mô phỏng bằng thông điệp vô hại.
