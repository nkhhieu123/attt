"""Tên module và tập nhãn đầu ra đã chốt (C01-T02).

Đây là hợp đồng giữa các phần mã: trích xuất đặc trưng, huấn luyện và giám sát
realtime đều import từ đây thay vì tự khai báo lại. Tham số có thể chỉnh (cửa
sổ, địa chỉ lab, đường dẫn) nằm trong config/default.yaml.
"""

from dataclasses import dataclass

MODULE_ANOMALY = "anomaly"
MODULE_ATTACK = "attack_classification"
MODULE_BOTNET = "botnet_topology"
MODULES = (MODULE_ANOMALY, MODULE_ATTACK, MODULE_BOTNET)

# Anomaly: Gaussian đa biến học từ traffic bình thường.
ANOMALY_LABELS = ("normal", "anomaly")

# Attack classification: Random Forest, so sánh với Logistic Regression.
ATTACK_LABELS = ("benign", "port_scan", "dos")

# Botnet/topology: host nghi vấn (theo host-cửa sổ) và cấu trúc đồ thị.
# Hai nhóm nhãn được đánh giá và báo cáo riêng.
BOTNET_HOST_LABELS = ("normal_host", "suspect_host")
TOPOLOGY_LABELS = ("centralized", "p2p", "none")

LABELS = {
    MODULE_ANOMALY: ANOMALY_LABELS,
    MODULE_ATTACK: ATTACK_LABELS,
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
        "Anomaly",
        "Gaussian đa biến, huấn luyện trên traffic bình thường",
        "Bình thường/bất thường và điểm bất thường",
    ),
    ModuleSpec(
        MODULE_ATTACK,
        "Attack classification",
        "Random Forest, so sánh với Logistic Regression",
        "Nhãn dự đoán: Benign, Port Scan, DoS",
    ),
    ModuleSpec(
        MODULE_BOTNET,
        "Botnet/topology",
        "Đặc trưng beaconing và đồ thị giao tiếp",
        "Host nghi vấn; cấu trúc tập trung/ngang hàng",
    ),
)
