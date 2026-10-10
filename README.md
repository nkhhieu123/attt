# attt

Đồ án: **Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng mạng**.

Hệ thống giám sát chạy trên Kali Linux trong mạng lab cô lập, gồm ba phần:

| Phần | Phương pháp | Đầu ra |
|---|---|---|
| Phát hiện bất thường | Gaussian đa biến học từ traffic bình thường | Bình thường/bất thường và điểm bất thường |
| Phân loại | Random Forest, so sánh với Logistic Regression | Benign, Port Scan, DoS |
| Botnet | Đặc trưng giao tiếp và đồ thị | Host nghi vấn, cấu trúc tập trung/ngang hàng |

Bản đầu tiên chỉ xuất cảnh báo ra terminal và file CSV; dashboard làm sau.

## Tiến độ

- [x] Bước 1 — Chốt phạm vi: [docs/01_pham_vi.md](docs/01_pham_vi.md)
- [ ] Các bước tiếp theo: dựng lab, trích xuất đặc trưng, huấn luyện ba module, giám sát realtime, kiểm thử theo kịch bản.

Báo cáo tiến độ: [docs/Bao_cao_tien_do_Buoc_1.docx](docs/Bao_cao_tien_do_Buoc_1.docx)

## Cấu trúc

```
docs/               Tài liệu phạm vi và báo cáo tiến độ
src/nids/scope.py   Module, tập nhãn, tham số cửa sổ, địa chỉ lab
src/nids/alerts.py  Schema cảnh báo, xuất terminal + CSV
tests/              Kiểm thử
```

## Chạy thử

Yêu cầu Python 3.10 trở lên, chưa cần cài thêm thư viện.

```bash
# Kiểm thử
python -m unittest discover -s tests

# Xuất cảnh báo mẫu để kiểm tra định dạng (không phải kết quả thực nghiệm)
PYTHONPATH=src python -m nids.alerts
```

Trên Windows PowerShell: `$env:PYTHONPATH = "src"; python -m nids.alerts`
