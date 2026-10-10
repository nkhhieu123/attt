"""Phạm vi đã chốt của đồ án (Bước 1).

File này là nguồn duy nhất cho tên module, tập nhãn, tham số cửa sổ và địa chỉ
lab. Các bước sau (trích xuất đặc trưng, huấn luyện, giám sát realtime) phải
import từ đây thay vì tự khai báo lại, để dữ liệu huấn luyện và realtime dùng
chung một quy ước.
"""

from dataclasses import dataclass

# --- Ba phần của đồ án -------------------------------------------------------

MODULE_ANOMALY = "anomaly"
MODULE_CLASSIFIER = "classifier"
MODULE_BOTNET = "botnet"
MODULES = (MODULE_ANOMALY, MODULE_CLASSIFIER, MODULE_BOTNET)

# Phần 1 - Phát hiện bất thường: Gaussian đa biến học từ traffic bình thường.
ANOMALY_LABELS = ("normal", "anomaly")

# Phần 2 - Phân loại: Random Forest, so sánh với Logistic Regression.
CLASSIFIER_LABELS = ("benign", "port_scan", "dos")

# Phần 3 - Botnet: host nghi vấn (theo host-cửa sổ) và cấu trúc đồ thị.
# Topology được báo cáo riêng, không gộp vào kết quả phát hiện host botnet.
BOTNET_HOST_LABELS = ("normal_host", "suspect_host")
TOPOLOGY_LABELS = ("centralized", "p2p", "none")

LABELS = {
    MODULE_ANOMALY: ANOMALY_LABELS,
    MODULE_CLASSIFIER: CLASSIFIER_LABELS,
    MODULE_BOTNET: BOTNET_HOST_LABELS + TOPOLOGY_LABELS,
}

# Nhãn không sinh cảnh báo (trạng thái bình thường của từng module).
NON_ALERT_LABELS = frozenset({"normal", "benign", "normal_host", "none"})


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    title: str
    method: str
    output: str


MODULE_SPECS = (
    ModuleSpec(
        MODULE_ANOMALY,
        "Phát hiện bất thường",
        "Gaussian đa biến, huấn luyện trên traffic bình thường",
        "Bình thường/bất thường và điểm bất thường",
    ),
    ModuleSpec(
        MODULE_CLASSIFIER,
        "Phân loại traffic",
        "Random Forest, so sánh với Logistic Regression",
        "Nhãn dự đoán: Benign, Port Scan, DoS",
    ),
    ModuleSpec(
        MODULE_BOTNET,
        "Phát hiện botnet",
        "Đặc trưng giao tiếp/đồ thị",
        "Host nghi vấn, cấu trúc tập trung/ngang hàng",
    ),
)

# --- Tham số cửa sổ ban đầu (giây) -------------------------------------------
# Được điều chỉnh trên tập validation, sau đó giữ cố định khi kiểm thử.


@dataclass(frozen=True)
class Window:
    size_s: int
    step_s: int


FLOW_WINDOW = Window(size_s=10, step_s=2)      # đặc trưng flow/host
GRAPH_WINDOW = Window(size_s=120, step_s=10)   # đặc trưng beaconing/đồ thị

# --- Mạng lab cô lập ---------------------------------------------------------

LAB_SUBNET = "192.168.50.0/24"
LAB_HOSTS = {
    "192.168.50.10": "Máy giám sát Kali Linux",
    "192.168.50.20": "Máy thử nghiệm",
    "192.168.50.30": "Máy chủ dịch vụ",
    "192.168.50.41": "Client/Bot mô phỏng 1",
    "192.168.50.42": "Client/Bot mô phỏng 2",
    "192.168.50.43": "Client/Bot mô phỏng 3",
    "192.168.50.50": "Server điều phối mô phỏng",
}

# --- Kênh xuất của bản đầu tiên ----------------------------------------------
# Chỉ terminal và file CSV. Dashboard nằm ngoài phạm vi bản đầu tiên.

OUTPUT_CHANNELS = ("terminal", "csv")
DEFAULT_ALERT_CSV = "output/alerts.csv"
