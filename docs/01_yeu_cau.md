# C01-T01 — Bảng yêu cầu bắt buộc và tùy chọn

Đề tài: **Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng mạng**

Bảng này rút từ kịch bản triển khai và kiểm thử của đồ án. Cột "Nguồn" là số
mục trong kịch bản. Cột "Chặng" để trống cho tới khi chốt kế hoạch các chặng sau.

- **Bắt buộc (B)**: kịch bản dùng từ "phải", "không được" hoặc mô tả là việc hệ thống thực hiện.
- **Tùy chọn (T)**: kịch bản dùng từ "có thể", "nếu", "khi đủ", hoặc ghi rõ làm sau.

## 1. Yêu cầu bắt buộc

| Mã | Yêu cầu | Nguồn |
|---|---|---|
| B01 | Chương trình giám sát chạy trên Kali Linux, bắt gói tin và lưu PCAP | 1, 4, 5 |
| B02 | Ghép flow hai chiều có quy định timeout; tính đặc trưng theo cửa sổ flow/host (10 giây, bước 2 giây) và beaconing/đồ thị (120 giây, bước 10 giây) | 4 |
| B03 | Module phát hiện bất thường: Gaussian đa biến huấn luyện trên traffic bình thường, cho điểm bất thường và quyết định cảnh báo | 1, 3 |
| B04 | Module phân loại traffic: Random Forest, so sánh với Logistic Regression, ba lớp Benign / Port Scan / DoS | 1, 3 |
| B05 | Module botnet: đặc trưng giao tiếp/đồ thị, đầu ra là host nghi vấn | 1, 3 |
| B06 | Phân tích topology: nhận diện cấu trúc tập trung hoặc ngang hàng; kết quả báo cáo riêng với phát hiện botnet trên dữ liệu thực | 3, 8, 9 |
| B07 | Ba module chạy song song; Gaussian không là cổng lọc bắt buộc cho hai module còn lại | 4 |
| B08 | Hợp nhất và ghi cảnh báo | 1, 4 |
| B09 | Dữ liệu: tập con CIC-IDS2017 (bất thường, phân loại), flow có nhãn của các scenario CTU-13 (botnet), PCAP tự thu trong lab | 3 |
| B10 | Mỗi lần thử nghiệm có nhật ký: mã lần chạy, thời gian bắt đầu/kết thúc, IP tham gia, hành vi; nhật ký là cơ sở gán nhãn, độc lập với dự đoán | 3 |
| B11 | Tách train/validation/test theo lần thu hoặc scenario; không để cửa sổ chồng lấn của cùng lần chạy ở cả train và test; chỉ học tham số tiền xử lý từ train | 3 |
| B12 | Huấn luyện và realtime dùng cùng quy tắc cửa sổ, đặc trưng, tiền xử lý; cửa sổ chỉnh trên validation rồi giữ cố định khi kiểm thử | 4 |
| B13 | Mạng lab ảo cô lập 7 node theo bảng địa chỉ; mirror traffic về Kali; kiểm tra Kali thấy cả hai chiều trước khi chạy mô hình | 2 |
| B14 | Kịch bản 1 — traffic bình thường 10 phút, có tác vụ kiểm tra trạng thái định kỳ; đo báo động giả | 5 |
| B15 | Kịch bản 2 — quét cổng bằng Nmap, lần chạy chậm và nhanh riêng biệt, có traffic bình thường trước và sau | 6 |
| B16 | Kịch bản 3 — DoS một nguồn, tải cao có giới hạn 60 giây, ba mức tải xác định trước | 7 |
| B17 | Kịch bản 4 — botnet tập trung mô phỏng: chu kỳ cố định và chu kỳ biến thiên, mỗi lần ít nhất 10 phút, có lần chạy đối chứng dịch vụ hợp lệ | 8 |
| B18 | Kịch bản 5 — botnet P2P mô phỏng: thay đổi chu kỳ và danh sách peer, mỗi lần ít nhất 10 phút, có đối chứng ngang hàng lành tính | 9 |
| B19 | Mỗi kịch bản lặp tối thiểu ba lần với lịch khác nhau; các lần kiểm thử cuối không dùng để chỉnh mô hình hoặc ngưỡng | 10 |
| B20 | Báo cáo chỉ số: Precision/Recall/F1 và tỷ lệ báo động giả (bất thường); Macro-F1, Precision/Recall từng lớp, confusion matrix (phân loại); Precision/Recall mức host–cửa sổ (botnet); confusion matrix topology; độ trễ, tốc độ xử lý, mất gói, CPU, RAM (realtime) | 10 |
| B21 | Độ trễ tính từ lúc hành vi bắt đầu đến cảnh báo phù hợp đầu tiên, gồm cả thời gian tích lũy cửa sổ; lần không phát hiện ghi là bỏ sót | 10 |
| B22 | Trình diễn theo thứ tự: bình thường → quét cổng → DoS → tập trung → P2P | 10 |
| B23 | Sản phẩm bàn giao: script đọc PCAP tạo flow/host/đồ thị; notebook huấn luyện, chọn ngưỡng, đánh giá; chương trình realtime; script sinh traffic và nhật ký nhãn; PCAP, file cảnh báo, ảnh demo, bảng chỉ số; tài liệu kiến trúc, hướng dẫn chạy, phân tích phát hiện sai | 11 |
| B24 | An toàn: chỉ thử nghiệm trong mạng cô lập do nhóm quản lý; botnet mô phỏng bằng thông điệp vô hại, không dùng mã độc | 1 |
| B25 | Trung thực: kết quả báo cáo lấy từ thực nghiệm; cảnh báo botnet chỉ thể hiện mức nghi vấn; "kết quả mong đợi" không trình bày như kết quả đã đạt | 8, 11 |

## 2. Yêu cầu tùy chọn hoặc có điều kiện

| Mã | Yêu cầu | Điều kiện / ghi chú | Nguồn |
|---|---|---|---|
| T01 | Mở rộng sang DDoS | Phải có nhiều nguồn phát và ghi nhận kết quả riêng | 7 |
| T02 | Chạy DoS với cả SYN và ICMP | Kịch bản cho phép chọn một loại; nhãn và mẫu huấn luyện phải khớp loại được thử | 7 |
| T03 | Đánh giá riêng traffic chưa có trong dữ liệu huấn luyện | Chỉ phát sinh khi thử loại traffic ngoài tập huấn luyện; khi đó đánh giá bằng module bất thường | 7 |
| T04 | So sánh Random Forest và Logistic Regression cho botnet | Khi đủ nhãn | 3 |
| T05 | Hiển thị đồ thị giao tiếp khi trình diễn | "Nếu có" | 10 |
| T06 | Dashboard | Làm sau khi các module chạy đúng; bản đầu tiên chỉ cần terminal và CSV | Ghi chú Bước 1 |

## 3. Ngoài phạm vi

- Dùng mã độc thật hoặc thử nghiệm ngoài mạng lab.
- Tự động chặn hoặc phản ứng với tấn công; hệ thống chỉ phát hiện và ghi cảnh báo.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Yêu cầu bắt buộc / tùy chọn | Bắt buộc là phải làm mới đạt đề bài; tùy chọn là làm thêm nếu có điều kiện |
| Kali Linux | Bản Linux chuyên cho kiểm thử bảo mật; là máy giám sát của lab |
| Bắt gói tin (capture) | Ghi lại các gói tin đi qua card mạng vào file |
| Flow hai chiều | Tất cả gói tin qua lại giữa hai đầu của một kết nối (cùng IP, cổng, giao thức), gộp cả chiều đi và chiều về |
| Timeout | Khoảng thời gian không có gói mới thì coi flow đã kết thúc |
| Đặc trưng (feature) | Con số tính từ dữ liệu để đưa vào mô hình, ví dụ số gói, số cổng đích khác nhau |
| Cửa sổ, bước | Cửa sổ là đoạn thời gian cố định để gom số liệu (ví dụ 10 giây); bước là khoảng dời cửa sổ mỗi lần (ví dụ 2 giây), nên các cửa sổ chồng lên nhau |
| Beaconing | Máy bị nhiễm định kỳ gọi về máy chủ điều khiển theo chu kỳ đều |
| Gaussian đa biến | Mô hình thống kê mô tả dữ liệu bình thường; mẫu nằm quá xa bị coi là bất thường |
| Điểm bất thường (score) | Con số cho biết mẫu khác bình thường bao nhiêu; vượt ngưỡng thì cảnh báo |
| Random Forest, Logistic Regression | Hai mô hình phân loại; Random Forest gồm nhiều cây quyết định bỏ phiếu, Logistic Regression tính xác suất từ tổng có trọng số |
| Benign / Port Scan / DoS | Bình thường / quét cổng (dò xem máy mở những cổng nào) / tấn công từ chối dịch vụ (làm máy chủ quá tải) |
| DDoS | DoS phân tán: nhiều máy cùng tấn công một đích |
| SYN, ICMP | SYN là gói mở kết nối TCP; tấn công SYN gửi ồ ạt gói này mà không hoàn tất kết nối. ICMP là giao thức của lệnh ping; tấn công ICMP gửi ồ ạt gói ping |
| Botnet, host nghi vấn | Botnet là mạng máy bị nhiễm cùng nghe lệnh; host nghi vấn là máy có hành vi giống bot |
| Topology tập trung / ngang hàng (P2P) | Tập trung: các bot cùng nói chuyện với một máy điều khiển. Ngang hàng: các bot nói chuyện trực tiếp với nhau, không có máy trung tâm |
| Peer | Một máy ngang hàng trong mạng P2P |
| Cổng lọc | Bước bắt buộc phải qua trước; ở đây nghĩa là module anomaly không quyết định thay cho hai module kia |
| CIC-IDS2017, CTU-13 | Hai bộ dữ liệu công khai có nhãn: CIC-IDS2017 về tấn công mạng, CTU-13 về botnet |
| Scenario | Một lần thu dữ liệu riêng trong CTU-13, mỗi lần với một loại bot |
| Nhãn, gán nhãn | Nhãn là đáp án đúng của mỗi mẫu (bình thường hay tấn công gì); gán nhãn là việc ghi đáp án đó |
| Train / validation / test | Ba phần dữ liệu: train để mô hình học, validation để chọn tham số và ngưỡng, test để đánh giá cuối cùng |
| Tiền xử lý | Biến đổi dữ liệu trước khi đưa vào mô hình, ví dụ đưa các đặc trưng về cùng thang đo |
| Realtime | Chạy trực tiếp trên traffic đang diễn ra, trái với offline là chạy trên file đã lưu |
| Node | Một máy trong mạng lab |
| Mirror traffic | Cấu hình switch sao chép mọi gói đi qua sang cổng của máy giám sát, để Kali thấy được traffic của các máy khác |
| Nmap | Công cụ quét cổng phổ biến |
| Báo động giả | Hệ thống cảnh báo trong khi thực ra không có tấn công (false positive) |
| Đối chứng | Lần chạy có hành vi lành tính trông giống tấn công, để kiểm tra mô hình không cảnh báo nhầm |
| Precision / Recall / F1 | Precision: trong các cảnh báo, bao nhiêu phần đúng. Recall: trong các tấn công thật, bắt được bao nhiêu phần. F1: điểm gộp cân bằng hai chỉ số trên |
| Macro-F1 | Trung bình F1 của từng lớp, mỗi lớp nặng như nhau, để lớp ít mẫu không bị lấn át |
| Confusion matrix | Bảng đếm mỗi lớp thật bị đoán thành lớp nào; đường chéo là đoán đúng |
| Độ trễ phát hiện | Thời gian từ lúc tấn công bắt đầu tới cảnh báo đúng đầu tiên |
| Mất gói | Gói đi qua mạng nhưng máy giám sát không kịp ghi lại |
| Notebook | File Jupyter chứa mã, kết quả và biểu đồ xen kẽ, dùng cho huấn luyện và phân tích |
| Script | Chương trình nhỏ chạy bằng một lệnh |
| Dashboard | Trang giao diện hiển thị số liệu và cảnh báo trực quan |
