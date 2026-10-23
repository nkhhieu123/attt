# Kế hoạch triển khai đồ án học máy phát hiện tấn công mạng

*Ứng dụng Python giám sát lưu lượng mạng trên Kali Linux*

Tài liệu tổ chức công việc thành 12 chặng và 82 task. Nội dung được trình bày theo thứ tự: tổng quan các giai đoạn, task chi tiết và tiêu chí nghiệm thu, tài liệu tham khảo.

Đây là kế hoạch triển khai, chưa phải kết quả thực nghiệm. Dashboard web và tự động chặn IP là phần tùy chọn.

## PHẦN I CÁC GIAI ĐOẠN TRIỂN KHAI

### Bốn giai đoạn theo đề cương

Bốn giai đoạn dưới đây mô tả quy trình tổng thể của đồ án. Mười hai chặng phía sau phân rã quy trình này thành công việc cụ thể; Phần II giữ các mã task để triển khai và nghiệm thu.

#### Mục đích

- Hiểu quy trình chuyển đổi log dịch vụ và file PCAP thành dữ liệu có cấu trúc phục vụ phân tích và huấn luyện học máy.
- Nắm được cấu trúc log dạng text, dữ liệu packet và cách đọc, phân tích bằng công cụ lập trình.
- Ứng dụng học máy vào phát hiện bất thường mạng, phân loại tấn công và phát hiện giao tiếp hoặc cấu trúc liên kết botnet.
- Triển khai mô hình trên Linux để thu thập lưu lượng, phát hiện và phân loại hành vi nghi vấn trong quá trình hoạt động.

### Giai đoạn 1 Chuyển đổi log và traffic thành dữ liệu có cấu trúc

#### Thu thập và tìm hiểu dữ liệu

- Khảo sát các nguồn PCAP công khai qua NETRESEC; lựa chọn dữ liệu cụ thể từ CIC-IDS2017, CTU-13 hoặc dữ liệu lab theo từng bài toán. Ghi rõ nguồn, nhãn và phạm vi dữ liệu.
- Tìm hiểu Global Header, Packet Header, Packet Data và timestamp của định dạng PCAP; phân biệt với PCAPNG.
- Tìm hiểu Scapy, PyShark hoặc dpkt; chọn công cụ đọc packet cho pipeline. Đồng thời chọn một loại log dịch vụ và chuyển log text thành bảng.
- Trích xuất timestamp, IP nguồn/đích, giao thức, kích thước packet, port và cờ TCP khi các trường này tồn tại.

#### Tổ chức dữ liệu và trích xuất đặc trưng

- Gom packet theo flow dựa trên 5-tuple, ghép hai chiều khi tính số gói và byte gửi/nhận; quy định timeout và thời điểm đóng flow.
- Tạo bảng flow hoặc snapshot flow theo cửa sổ; tổng hợp thêm theo IP nguồn trong cửa sổ thời gian để quan sát nhiều kết nối của một host.
- Tính thống kê kích thước packet, khoảng cách thời gian giữa packet, số lượng và tỷ lệ cờ TCP.
- Tính thời lượng flow, tổng byte/packet theo hai chiều và tỷ lệ gửi/nhận. Ở cấp host, tổng hợp số hoặc tỷ lệ kết nối không hoàn tất sau thời gian quan sát quy định.
- Tính số IP đích, số cổng đích khác nhau, tần suất kết nối, entropy cổng đích và dấu hiệu kết nối lặp lại định kỳ.

Đầu ra: dữ liệu packet, log, flow và host có cấu trúc; tài liệu schema, công thức và cách gán nhãn. Chặng liên quan: 2–4; chặng 1 chuẩn bị dự án.

### Giai đoạn 2 Phân tích và phát hiện hành vi bất thường

- Chốt tập dữ liệu và nhãn cho từng bài toán; dùng EDA để thống kê phân bố đặc trưng và trực quan hóa sự khác biệt giữa traffic bình thường và tấn công.
- So sánh hành vi host bình thường và host thực hiện quét qua số cổng đích, số kết nối và các đặc trưng liên quan.
- Xử lý dữ liệu thiếu, giá trị vô hạn và mất cân bằng lớp. Tách train/validation/test theo phiên hoặc scenario trước khi học tham số tiền xử lý.
- Huấn luyện Gaussian trên dữ liệu bình thường; chọn ngưỡng bằng validation và đánh giá phát hiện bất thường trên test.
- Huấn luyện mô hình supervised như Random Forest để phân loại các lớp có đủ dữ liệu, trước hết là Benign, PortScan và DoS. Mở rộng brute-force, exploit hoặc DDoS khi có nhãn và kiểm thử tương ứng.
- Đánh giá Accuracy, Precision, Recall, F1, macro-F1 và confusion matrix; báo cáo riêng từng lớp và phân tích mất cân bằng dữ liệu.

Đầu ra: notebook EDA, dữ liệu đã chia, mô hình Gaussian, mô hình phân loại và bảng đánh giá. Chặng liên quan: 5–7.

### Giai đoạn 3 Phát hiện tấn công và phân tích botnet

- So sánh các thuật toán học máy trên cùng bài toán, tập đặc trưng và cách chia dữ liệu; có thí nghiệm so sánh ít nhất hai mô hình phát hiện botnet.
- Phân tích beaconing theo chuỗi kết nối từ một host tới cùng đích: chu kỳ, độ biến thiên và số quan sát. Thêm đối chứng lành tính vì kết nối định kỳ không tự chứng minh botnet.
- Xây dựng đồ thị giao tiếp theo cửa sổ, tính đặc trưng node/cạnh và nhận diện cấu trúc tập trung hoặc ngang hàng. Đánh giá topology riêng với phát hiện host nghi vấn.
- Tổng hợp kết quả của Gaussian, phân loại tấn công và phân tích botnet; phân tích ưu nhược điểm. Chỉ so trực tiếp chỉ số khi cùng nhãn mục tiêu và đơn vị đánh giá.
- Tích hợp các module chạy độc lập và thử chế độ tuần tự Gaussian → phân loại → kiểm tra botnet. Đo mức bỏ sót và thời gian xử lý để lựa chọn phương án.

Đầu ra: module botnet/đồ thị, kết quả centralized/P2P, bảng so sánh thuật toán và pipeline dự đoán offline. Chặng liên quan: 8–9.

### Giai đoạn 4 Triển khai hệ thống phát hiện thời gian thực

#### Triển khai và tích hợp

- Lưu mô hình, bộ tiền xử lý, ngưỡng và schema; cài Python cùng các thư viện thực sự sử dụng trên Kali Linux.
- Bắt packet bằng Scapy; bố trí cảm biến để thấy traffic cần giám sát. Gom flow và cửa sổ host/đồ thị theo cùng quy tắc đã dùng huấn luyện.
- Chạy chương trình nền theo quy trình bắt packet → trích xuất đặc trưng → mô hình → hợp nhất cảnh báo; quản lý hàng đợi, bộ nhớ và log.
- Ghi thời điểm sự kiện, thời điểm cảnh báo, IP liên quan, loại bất thường/tấn công, module và điểm dự đoán. Phân biệt điểm bất thường với xác suất phân loại.

#### Kiểm thử và đo lường

- Trong lab được phép, kiểm thử quét cổng bằng Nmap và traffic DoS có giới hạn, có thể dùng ICMP hoặc SYN phù hợp với dữ liệu. Một nguồn flood là DoS; thử nghiệm DDoS cần nhiều nguồn.
- Mô phỏng beaconing bằng thông điệp vô hại; kiểm thử cả giao tiếp tập trung, ngang hàng và các đối chứng lành tính.
- Lưu nhật ký ground truth, PCAP và cảnh báo; quan sát dự đoán thực tế trên Kali thay vì mặc định hệ thống luôn phát hiện đúng.
- Đo độ trễ gồm cả thời gian chờ cửa sổ, tỷ lệ phát hiện, bỏ sót, báo động giả và tài nguyên. Đối chiếu kết quả realtime với test offline.
- Tùy chọn nâng cao: dashboard hiển thị traffic và đồ thị giao tiếp; tích hợp firewall sau khi đã đánh giá rủi ro chặn nhầm.

Đầu ra: chương trình realtime trên Kali, bằng chứng kiểm thử và báo cáo bàn giao. Chặng liên quan: 10–12.

### Kết quả cần đạt và bằng chứng

- Pipeline PCAP/log → dữ liệu có cấu trúc, kèm schema và ví dụ đối chiếu.
- Mô hình Gaussian và bộ phân loại đa lớp có kết quả đánh giá trên dữ liệu test.
- Module botnet có bảng so sánh ML; module topology có kết quả tập trung/ngang hàng và đối chứng.
- Hệ thống Python chạy trên Kali, có log và ít nhất 2–3 tình huống tấn công mô phỏng; bổ sung các tình huống topology để kiểm chứng yêu cầu botnet.
- Báo cáo quy trình, notebook huấn luyện, mã nguồn, ảnh/log demo, độ trễ, độ chính xác thực nghiệm và hướng dẫn tái lập.

### Phân rã thành 12 chặng triển khai

### Chặng 01 Chốt yêu cầu và khởi tạo dự án

Mục tiêu: Chốt phạm vi, yêu cầu và thiết lập môi trường phát triển.

Đầu ra và tiêu chí hoàn thành: Cài được dự án trong môi trường mới; mỗi yêu cầu có chặng phụ trách.

### Chặng 02 Khảo sát dữ liệu và định dạng

Mục tiêu: Xác định nguồn dữ liệu, định dạng và căn cứ gán nhãn.

Đầu ra và tiêu chí hoàn thành: Biết chính xác dữ liệu nào phục vụ từng bài toán. Không coi NETRESEC là một dataset thống nhất có sẵn nhãn.

### Chặng 03 Chuyển PCAP và log thành dữ liệu có cấu trúc

Mục tiêu: Đọc dữ liệu thô và chuyển thành bản ghi có cấu trúc.

Đầu ra và tiêu chí hoàn thành: Có cả ví dụ PCAP → bản ghi packet và log text → bảng dữ liệu. Log dịch vụ có thể dùng để đối chiếu sự kiện, không bắt buộc đưa vào mọi mô hình.

### Chặng 04 Xây dựng flow và đặc trưng

Mục tiêu: Tổng hợp giao tiếp mạng thành flow và đặc trưng host.

Đầu ra và tiêu chí hoàn thành: Công thức, đơn vị và trường hợp biên được ghi rõ; đặc trưng không dùng dữ liệu tương lai. SYN thiếu phản hồi được coi là dấu hiệu nghi vấn, không tự động gán nhãn scan.

### Chặng 05 Gán nhãn EDA và chia dữ liệu

Mục tiêu: Tạo dữ liệu huấn luyện sạch, có nhãn và tránh rò rỉ.

Đầu ra và tiêu chí hoàn thành: Dữ liệu sẵn sàng huấn luyện, có giải thích cách tránh rò rỉ giữa các tập.

### Chặng 06 Gaussian anomaly detection

Mục tiêu: Học phân bố bình thường và phát hiện mẫu bất thường.

Đầu ra và tiêu chí hoàn thành: Nạp lại mô hình để dự đoán được; có kết quả test thật và phân tích hạn chế của giả định Gaussian.

### Chặng 07 Phân loại tấn công đa lớp

Mục tiêu: Huấn luyện và so sánh mô hình phân loại loại tấn công.

Đầu ra và tiêu chí hoàn thành: Có bảng so sánh hai mô hình trên cùng bài toán. Brute-force, exploit hoặc DDoS chỉ thêm khi có dữ liệu và kiểm thử tương ứng.

### Chặng 08 Botnet và nhận diện topology

Mục tiêu: Phát hiện host nghi vấn và đánh giá cấu trúc giao tiếp botnet.

Đầu ra và tiêu chí hoàn thành: Có bảng so sánh ML botnet và kết quả centralized/P2P. Không dùng topology đơn thuần để kết luận có mã độc.

### Chặng 09 Tích hợp pipeline offline

Mục tiêu: Kết nối các module thành chương trình dự đoán từ PCAP.

Đầu ra và tiêu chí hoàn thành: Chạy được bằng CLI. Chỉ so trực tiếp các chỉ số khi cùng nhãn mục tiêu, đơn vị đánh giá và tập dữ liệu.

### Chặng 10 Triển khai realtime trên Kali

Mục tiêu: Vận hành cảm biến và mô hình trên traffic trực tiếp.

Đầu ra và tiêu chí hoàn thành: Chương trình chạy nền được, ghi cảnh báo và khởi động/dừng theo hướng dẫn.

### Chặng 11 Kiểm thử thực nghiệm

Mục tiêu: Đo hiệu quả hệ thống bằng kịch bản lab có nhãn chuẩn.

Đầu ra và tiêu chí hoàn thành: Lưu PCAP, log, ảnh và số liệu. Độ trễ bao gồm thời gian tích lũy cửa sổ; lần không phát hiện phải tính là bỏ sót.

### Chặng 12 Báo cáo và bàn giao

Mục tiêu: Hoàn thiện bằng chứng, hướng dẫn và sản phẩm bàn giao.

Đầu ra và tiêu chí hoàn thành: Mọi yêu cầu bắt buộc có sản phẩm và bằng chứng tương ứng. Dashboard và tự động chặn IP vẫn là tùy chọn.

### Nguyên tắc thực hiện

- Dùng mã Cxx-Txx để quản lý task trên GitHub. Hoàn thành và kiểm tra từng task trước khi đánh dấu tiến độ.
- Dùng chung logic trích xuất đặc trưng offline và realtime; ghi rõ schema, đơn vị và quy tắc cửa sổ.
- Chỉ fit tiền xử lý trên train; chọn ngưỡng và tham số bằng validation; giữ test để đánh giá cuối.
- Chỉ thử nghiệm trong mạng lab được phép; mô phỏng giao tiếp botnet bằng thông điệp vô hại.
- Lưu bằng chứng thực nghiệm. Không dùng kết quả mong đợi thay cho số liệu đã đo.

## PHẦN II TASK CHI TIẾT VÀ TIÊU CHÍ NGHIỆM THU

### Chặng 01 Chốt yêu cầu và khởi tạo dự án

- **C01-T01** Lập bảng yêu cầu bắt buộc và tùy chọn từ đề bài.
- **C01-T02** Chốt đầu ra ba module: anomaly, attack classification, botnet/topology.
- **C01-T03** Tạo repository và cấu trúc thư mục.
- **C01-T04** Tạo môi trường Python, dependencies và .gitignore.
- **C01-T05** Tạo README, cấu hình chung và nhật ký quyết định kỹ thuật.

**Nghiệm thu:** Cài được dự án trong môi trường mới; mỗi yêu cầu có chặng phụ trách.

### Chặng 02 Khảo sát dữ liệu và định dạng

- **C02-T01** Viết mô tả Global Header, Packet Header, Packet Data của PCAP; phân biệt với PCAPNG.
- **C02-T02** Chọn một loại log dịch vụ, chẳng hạn access log của web server.
- **C02-T03** Chọn tập con CIC-IDS2017 cho phân loại.
- **C02-T04** Kiểm tra các scenario CTU-13, file khả dụng và ý nghĩa nhãn.
- **C02-T05** Tạo manifest: nguồn, file, thời gian, nhãn, mục đích sử dụng.
- **C02-T06** Chốt dữ liệu còn phải tự thu trong lab.

**Nghiệm thu:** Biết chính xác dữ liệu nào phục vụ từng bài toán. Không coi NETRESEC là một dataset thống nhất có sẵn nhãn.

### Chặng 03 Chuyển PCAP và log thành dữ liệu có cấu trúc

- **C03-T01** Viết bộ đọc PCAP theo từng packet.
- **C03-T02** Trích xuất timestamp, IP, giao thức, độ dài.
- **C03-T03** Trích xuất port và cờ TCP khi tồn tại.
- **C03-T04** Xử lý packet không hỗ trợ, lỗi và thống kê bỏ qua.
- **C03-T05** Viết parser cho log dịch vụ đã chọn.
- **C03-T06** Xuất dữ liệu log thành bảng; đối chiếu một số dòng với bản gốc.
- **C03-T07** Đối chiếu kết quả đọc packet với Wireshark.

**Nghiệm thu:** Có cả ví dụ PCAP → bản ghi packet và log text → bảng dữ liệu. Log dịch vụ có thể dùng để đối chiếu sự kiện, không bắt buộc đưa vào mọi mô hình.

### Chặng 04 Xây dựng flow và đặc trưng

- **C04-T01** Định nghĩa flow hai chiều và quy tắc forward/backward.
- **C04-T02** Xử lý timeout, FIN/RST và tái sử dụng 5-tuple.
- **C04-T03** Tính packet, byte, thời lượng và tỷ lệ gửi/nhận.
- **C04-T04** Tính thống kê kích thước, inter-arrival time và cờ TCP.
- **C04-T05** Xây dựng cửa sổ host theo thời gian packet.
- **C04-T06** Tính số đích, cổng đích, kết nối mới và entropy cổng.
- **C04-T07** Tính tỷ lệ kết nối không hoàn tất sau thời gian quan sát quy định.
- **C04-T08** Xuất bảng đặc trưng cùng schema và metadata.

**Nghiệm thu:** Công thức, đơn vị và trường hợp biên được ghi rõ; đặc trưng không dùng dữ liệu tương lai. SYN thiếu phản hồi được coi là dấu hiệu nghi vấn, không tự động gán nhãn scan.

### Chặng 05 Gán nhãn EDA và chia dữ liệu

- **C05-T01** Ghép nhãn từ nguồn và metadata phù hợp.
- **C05-T02** Báo cáo mẫu khớp, không khớp và mơ hồ.
- **C05-T03** Định nghĩa nhãn cho cửa sổ chứa nhiều hành vi.
- **C05-T04** Chia train/validation/test theo phiên hoặc scenario.
- **C05-T05** Kiểm tra thiếu, vô hạn, trùng và phân bố lớp.
- **C05-T06** Vẽ EDA cho các đặc trưng chính.
- **C05-T07** Xây dựng tiền xử lý; chỉ fit và cân bằng lớp trên train.

**Nghiệm thu:** Dữ liệu sẵn sàng huấn luyện, có giải thích cách tránh rò rỉ giữa các tập.

### Chặng 06 Gaussian anomaly detection

- **C06-T01** Chọn đặc trưng và lấy mẫu bình thường trong train.
- **C06-T02** Kiểm tra phân bố và xác định phép biến đổi cần thiết.
- **C06-T03** Huấn luyện Gaussian, xử lý covariance suy biến.
- **C06-T04** Tính điểm bất thường và chọn ngưỡng trên validation.
- **C06-T05** Đánh giá Precision, Recall, F1 và false positive rate.
- **C06-T06** Lưu mô hình, ngưỡng, tiền xử lý và notebook.

**Nghiệm thu:** Nạp lại mô hình để dự đoán được; có kết quả test thật và phân tích hạn chế của giả định Gaussian.

### Chặng 07 Phân loại tấn công đa lớp

- **C07-T01** Chốt nhãn thực tế, bắt đầu với Benign, PortScan và DoS.
- **C07-T02** Huấn luyện Logistic Regression làm mô hình đối chiếu.
- **C07-T03** Huấn luyện Random Forest.
- **C07-T04** Chọn tham số và mô hình bằng validation.
- **C07-T05** Đánh giá macro-F1, chỉ số từng lớp và confusion matrix.
- **C07-T06** Phân tích nhầm lẫn và lưu artifact.

**Nghiệm thu:** Có bảng so sánh hai mô hình trên cùng bài toán. Brute-force, exploit hoặc DDoS chỉ thêm khi có dữ liệu và kiểm thử tương ứng.

### Chặng 08 Botnet và nhận diện topology

- **C08-T01** Xây dựng đồ thị theo cửa sổ: node, cạnh, trọng số.
- **C08-T02** Tính số peer, bậc vào/ra, tính tương hỗ và mức tập trung.
- **C08-T03** Tính đặc trưng beaconing với số quan sát tối thiểu.
- **C08-T04** Chuẩn bị dữ liệu host–cửa sổ có nhãn botnet; quy định cách xử lý Background.
- **C08-T05** Huấn luyện và so sánh ít nhất hai mô hình phát hiện botnet.
- **C08-T06** Tạo dữ liệu topology tập trung, ngang hàng và đối chứng lành tính.
- **C08-T07** Xây dựng bộ nhận diện topology; ghi rõ dùng quy tắc hay ML.
- **C08-T08** Đánh giá phát hiện botnet và nhận diện topology bằng hai bảng riêng.

**Nghiệm thu:** Có bảng so sánh ML botnet và kết quả centralized/P2P. Không dùng topology đơn thuần để kết luận có mã độc.

Lưu ý: Nếu dữ liệu CTU-13 không cung cấp được một đặc trưng, phải chọn tập đặc trưng chung hoặc làm thí nghiệm riêng; không ghép các cột có cách tính khác nhau.

### Chặng 09 Tích hợp pipeline offline

- **C09-T01** Viết bộ nạp artifact và kiểm tra schema.
- **C09-T02** Chạy PCAP qua toàn bộ pipeline.
- **C09-T03** Cho các module tạo đầu ra độc lập và hợp nhất cảnh báo.
- **C09-T04** Thêm chế độ Gaussian → classifier → kiểm tra botnet.
- **C09-T05** So sánh chế độ độc lập với tuần tự về bỏ sót và thời gian xử lý.
- **C09-T06** Ghi cảnh báo, điểm mô hình và gộp sự kiện lặp.

**Nghiệm thu:** Chạy được bằng CLI. Chỉ so trực tiếp các chỉ số khi cùng nhãn mục tiêu, đơn vị đánh giá và tập dữ liệu.

### Chặng 10 Triển khai realtime trên Kali

- **C10-T01** Clone và cài dự án trên Kali.
- **C10-T02** Xác minh vị trí cảm biến thấy traffic hai chiều.
- **C10-T03** Thêm nguồn packet live, tái sử dụng bộ trích xuất.
- **C10-T04** Thêm hàng đợi giới hạn và dọn state.
- **C10-T05** Đo packet xử lý, packet bị bỏ và tài nguyên.
- **C10-T06** Xử lý dừng chương trình và quản lý log.
- **C10-T07** Cấu hình chạy nền, chẳng hạn bằng systemd.
- **C10-T08** Kiểm tra tính nhất quán offline/realtime.

**Nghiệm thu:** Chương trình chạy nền được, ghi cảnh báo và khởi động/dừng theo hướng dẫn.

### Chặng 11 Kiểm thử thực nghiệm

- **C11-T01** Tạo nhật ký ground truth độc lập với dự đoán.
- **C11-T02** Kiểm thử traffic bình thường, gồm tác vụ định kỳ hợp lệ.
- **C11-T03** Kiểm thử port scan.
- **C11-T04** Kiểm thử DoS có giới hạn trong lab.
- **C11-T05** Kiểm thử giao tiếp tập trung mô phỏng.
- **C11-T06** Kiểm thử giao tiếp ngang hàng mô phỏng.
- **C11-T07** Chạy các đối chứng lành tính và lặp lại các tình huống.
- **C11-T08** Tổng hợp độ trễ, bỏ sót, báo động giả và hiệu năng.

**Nghiệm thu:** Lưu PCAP, log, ảnh và số liệu. Độ trễ bao gồm thời gian tích lũy cửa sổ; lần không phát hiện phải tính là bỏ sót.

### Chặng 12 Báo cáo và bàn giao

- **C12-T01** Hoàn thiện notebook cho ba hướng tiếp cận.
- **C12-T02** Tổng hợp bảng kết quả offline và realtime riêng.
- **C12-T03** Viết kiến trúc, hướng dẫn triển khai và tái lập.
- **C12-T04** Phân tích báo động giả, bỏ sót và giới hạn.
- **C12-T05** Lập bảng yêu cầu đề tài → mã nguồn → bằng chứng.
- **C12-T06** Kiểm tra clone và chạy từ môi trường mới.
- **C12-T07** Chuẩn bị kịch bản bảo vệ và bản phát lại PCAP.

**Nghiệm thu:** Mọi yêu cầu bắt buộc có sản phẩm và bằng chứng tương ứng. Dashboard và tự động chặn IP vẫn là tùy chọn.

## PHẦN III TÀI LIỆU THAM KHẢO

Các nguồn dưới đây phục vụ việc lựa chọn dữ liệu và triển khai. Khi viết báo cáo cuối, ghi rõ phiên bản thư viện và phiên bản hoặc scenario dữ liệu thực sự sử dụng.

### 1 NETRESEC PCAP Files

Danh mục nguồn PCAP công khai; dùng khi khảo sát dữ liệu ở chặng 2.

<https://www.netresec.com/?page=pcapfiles>

### 2 CIC IDS2017

Nguồn dữ liệu và mô tả kịch bản cho phần gán nhãn, phát hiện bất thường và phân loại ở chặng 2, 5, 6, 7.

<https://www.unb.ca/cic/datasets/ids-2017.html>

### 3 CTU 13 Dataset

Dữ liệu botnet và hướng dẫn nhãn cho chặng 8. Cần kiểm tra loại file khả dụng; không mặc định Background là Normal.

<https://www.stratosphereips.org/datasets-ctu13>

### 4 Scapy Documentation

Tham khảo đọc PCAP và bắt packet trong chặng 3 và 10.

<https://scapy.readthedocs.io/>

### 5 PyShark

Thư viện thay thế dùng TShark để phân tích packet; tham khảo khi cần phân tích sâu giao thức.

<https://github.com/KimiNewt/pyshark>

### 6 dpkt Documentation

Thư viện thay thế để đọc và phân tích dữ liệu packet.

<https://dpkt.readthedocs.io/>

### 7 scikit learn Documentation

Tiền xử lý, pipeline, mô hình và chỉ số đánh giá cho chặng 5 đến 8.

<https://scikit-learn.org/stable/>

### 8 NetworkX Documentation

Đồ thị và đặc trưng giao tiếp phục vụ chặng 8.

<https://networkx.org/documentation/stable/>

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Pipeline | Chuỗi bước xử lý nối tiếp nhau: đọc dữ liệu → trích đặc trưng → mô hình → cảnh báo |
| Scapy, PyShark, dpkt | Ba thư viện Python đọc gói tin; PyShark cần cài TShark |
| 5-tuple | Năm giá trị xác định một kết nối: IP nguồn, IP đích, cổng nguồn, cổng đích, giao thức |
| Flow, snapshot flow | Flow là toàn bộ gói của một kết nối; snapshot là trạng thái của flow tại một thời điểm trong cửa sổ |
| Forward / backward | Chiều đi (từ bên mở kết nối) / chiều về |
| Inter-arrival time | Khoảng thời gian giữa hai gói liên tiếp |
| Entropy cổng đích | Độ đa dạng của các cổng đích; quét cổng cho entropy cao vì chạm rất nhiều cổng khác nhau |
| Kết nối không hoàn tất | Có gói SYN mở kết nối nhưng không có phản hồi đầy đủ |
| Tái sử dụng 5-tuple | Cùng 5 giá trị nhưng là kết nối mới sau khi kết nối cũ đã đóng |
| EDA | Phân tích khám phá dữ liệu: thống kê và vẽ biểu đồ để hiểu dữ liệu trước khi huấn luyện |
| Supervised | Học có giám sát: mô hình học từ dữ liệu đã có nhãn đúng |
| Brute-force, exploit | Dò mật khẩu bằng cách thử liên tục / khai thác lỗ hổng phần mềm |
| Rò rỉ dữ liệu (data leakage) | Thông tin của tập test lọt vào lúc huấn luyện, làm kết quả đẹp giả tạo |
| Fit tiền xử lý | Tính tham số của bước tiền xử lý (ví dụ trung bình để chuẩn hóa) từ dữ liệu |
| Cân bằng lớp | Xử lý khi một lớp có quá ít mẫu so với lớp khác |
| Covariance suy biến | Ma trận hiệp phương sai không nghịch đảo được (ví dụ hai đặc trưng trùng nhau), làm mô hình Gaussian không tính được |
| False positive rate | Tỷ lệ mẫu bình thường bị cảnh báo nhầm |
| Accuracy | Tỷ lệ dự đoán đúng trên tổng số mẫu |
| Precision / Recall / F1 / macro-F1 | Tỷ lệ cảnh báo đúng / tỷ lệ tấn công bắt được / điểm cân bằng hai chỉ số / trung bình F1 của các lớp |
| Confusion matrix | Bảng đếm mỗi lớp thật bị đoán thành lớp nào |
| Artifact | Sản phẩm của bước huấn luyện cần lưu lại: mô hình, bộ tiền xử lý, ngưỡng |
| Node, cạnh, trọng số | Thành phần của đồ thị: điểm (máy), đường nối (có trao đổi), con số trên đường nối (ví dụ số kết nối) |
| Bậc vào / ra | Số máy gửi tới một máy / số máy mà nó gửi tới |
| Tính tương hỗ | Hai máy có liên lạc theo cả hai chiều hay không |
| Cảm biến (sensor) | Máy đặt ở vị trí thấy được traffic để bắt gói; ở đây là Kali |
| Hàng đợi, state | Hàng đợi chứa gói chờ xử lý; state là dữ liệu chương trình giữ trong bộ nhớ, như các flow đang mở |
| systemd | Hệ thống quản lý dịch vụ chạy nền của Linux |
| CLI | Giao diện dòng lệnh |
| Firewall | Tường lửa: chặn hoặc cho qua gói tin theo luật |
| scikit-learn, NetworkX | Thư viện Python cho học máy / cho đồ thị |
| Clone | Tải toàn bộ kho mã từ GitHub về máy |
