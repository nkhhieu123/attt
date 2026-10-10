"""Định dạng cảnh báo và kênh xuất của bản đầu tiên: terminal + file CSV.

Cả ba module (anomaly, classifier, botnet) đều phát cảnh báo qua cùng một
schema để có thể hợp nhất vào một file và đối chiếu với nhật ký kịch bản.
"""

import argparse
import csv
import sys
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from pathlib import Path

from . import scope


@dataclass
class Alert:
    module: str                 # một trong scope.MODULES
    label: str                  # nhãn thuộc scope.LABELS[module]
    window_start: float         # epoch giây, đầu cửa sổ quan sát
    window_end: float           # epoch giây, cuối cửa sổ quan sát
    src_ip: str = ""            # host nguồn / host nghi vấn
    dst_ip: str = ""            # host đích / node trung tâm
    score: float | None = None  # điểm bất thường hoặc xác suất của mô hình
    threshold: float | None = None
    run_id: str = ""            # mã lần chạy, khớp với nhật ký kịch bản
    detail: str = ""
    created_at: float | None = None  # thời điểm phát cảnh báo (tính độ trễ)

    def __post_init__(self):
        if self.module not in scope.MODULES:
            raise ValueError(f"module không hợp lệ: {self.module!r}")
        if self.label not in scope.LABELS[self.module]:
            raise ValueError(
                f"nhãn {self.label!r} không thuộc module {self.module!r}"
            )
        if self.window_end < self.window_start:
            raise ValueError("window_end phải >= window_start")
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc).timestamp()

    @property
    def is_alert(self) -> bool:
        return self.label not in scope.NON_ALERT_LABELS


CSV_COLUMNS = [f.name for f in fields(Alert)]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _num(x: float | None) -> str:
    return "" if x is None else f"{x:.6g}"


def to_row(alert: Alert) -> dict:
    row = asdict(alert)
    for key in ("window_start", "window_end", "created_at"):
        row[key] = _iso(row[key])
    for key in ("score", "threshold"):
        row[key] = _num(row[key])
    return row


def format_line(alert: Alert) -> str:
    """Một dòng cảnh báo cho terminal."""
    parts = [
        _iso(alert.created_at),
        f"[{alert.module}]",
        alert.label.upper(),
    ]
    if alert.src_ip or alert.dst_ip:
        parts.append(f"{alert.src_ip or '*'} -> {alert.dst_ip or '*'}")
    if alert.score is not None:
        score = f"score={_num(alert.score)}"
        if alert.threshold is not None:
            score += f" (ngưỡng {_num(alert.threshold)})"
        parts.append(score)
    if alert.run_id:
        parts.append(f"run={alert.run_id}")
    if alert.detail:
        parts.append(alert.detail)
    return " | ".join(parts)


class AlertSink:
    """Ghi cảnh báo ra terminal và nối vào file CSV.

    Mặc định chỉ ghi các dự đoán là cảnh báo; đặt ``log_all=True`` để lưu cả
    dự đoán bình thường (cần cho việc tính báo động giả và confusion matrix).
    """

    def __init__(self, csv_path=scope.DEFAULT_ALERT_CSV, stream=None, log_all=False):
        self.csv_path = Path(csv_path) if csv_path else None
        self.stream = stream if stream is not None else sys.stdout
        self.log_all = log_all
        self._file = None
        self._writer = None
        if self.csv_path:
            self.csv_path.parent.mkdir(parents=True, exist_ok=True)
            is_new = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
            self._file = self.csv_path.open("a", newline="", encoding="utf-8")
            self._writer = csv.DictWriter(self._file, fieldnames=CSV_COLUMNS)
            if is_new:
                self._writer.writeheader()

    def emit(self, alert: Alert) -> bool:
        """Trả về True nếu bản ghi được xuất."""
        if not (alert.is_alert or self.log_all):
            return False
        if alert.is_alert:
            print(format_line(alert), file=self.stream, flush=True)
        if self._writer:
            self._writer.writerow(to_row(alert))
            self._file.flush()
        return True

    def close(self):
        if self._file:
            self._file.close()
            self._file = None
            self._writer = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _demo_alerts(now: float) -> list[Alert]:
    """Cảnh báo MẪU để kiểm tra định dạng. Không phải kết quả thực nghiệm."""
    flow, graph = scope.FLOW_WINDOW.size_s, scope.GRAPH_WINDOW.size_s
    run = "MAU-DINH-DANG"
    return [
        Alert(scope.MODULE_ANOMALY, "anomaly", now - flow, now,
              src_ip="192.168.50.20", dst_ip="192.168.50.30",
              score=42.7, threshold=18.3, run_id=run, detail="mẫu định dạng"),
        Alert(scope.MODULE_CLASSIFIER, "port_scan", now - flow, now,
              src_ip="192.168.50.20", dst_ip="192.168.50.30",
              score=0.97, run_id=run, detail="mẫu định dạng"),
        Alert(scope.MODULE_CLASSIFIER, "dos", now - flow, now,
              src_ip="192.168.50.20", dst_ip="192.168.50.30",
              score=0.91, run_id=run, detail="mẫu định dạng"),
        Alert(scope.MODULE_BOTNET, "suspect_host", now - graph, now,
              src_ip="192.168.50.41", dst_ip="192.168.50.50",
              score=0.88, threshold=0.5, run_id=run, detail="mẫu định dạng"),
        Alert(scope.MODULE_BOTNET, "centralized", now - graph, now,
              dst_ip="192.168.50.50", run_id=run,
              detail="mẫu định dạng; node trung tâm ở cột dst_ip"),
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Xuất cảnh báo mẫu ra terminal và CSV để kiểm tra định dạng."
    )
    parser.add_argument("--csv", default="output/alerts_demo.csv",
                        help="đường dẫn file CSV (mặc định: %(default)s)")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print("*** CẢNH BÁO MẪU - chỉ để kiểm tra định dạng, không phải kết quả thực nghiệm ***")
    now = datetime.now(timezone.utc).timestamp()
    with AlertSink(args.csv) as sink:
        for alert in _demo_alerts(now):
            sink.emit(alert)
    print(f"Đã ghi CSV: {args.csv}")


if __name__ == "__main__":
    main()
