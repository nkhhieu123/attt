"""Đọc access log Nginx định dạng `nids` thành bản ghi có cấu trúc (C03-T05)
và xuất ra bảng CSV (C03-T06).

Định dạng và ý nghĩa 12 trường mô tả trong docs/05_log_dich_vu.md:

    log_format nids '$msec $remote_addr $remote_port $server_port '
                    '"$request" $status $body_bytes_sent $request_length '
                    '$request_time $connection $connection_requests '
                    '"$http_user_agent"';

Nginx thay ký tự ", \\, ký tự điều khiển và byte ngoài ASCII trong chuỗi bằng
dạng \\xHH; parser giải mã lại thành chuỗi gốc. Dòng không đúng định dạng bị bỏ
qua kèm lý do và được đếm trong LogStats, giống cách packets.py xử lý packet.

    stats = LogStats()
    for rec in read_log("data/service_logs/k1-binh-thuong-train-01/access_nids.log", stats):
        print(rec.ts_ns, rec.client_ip, rec.client_port, rec.status, rec.request_time_ms)
    print("\\n".join(stats.summary_lines()))
"""

import argparse
import csv
import gzip
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path

LOG_FORMAT_NAME = "nids"

LINE_RE = re.compile(
    r'(?P<ts>\d+\.\d{3}) '
    r'(?P<client_ip>\S+) '
    r'(?P<client_port>\d+|-) '
    r'(?P<server_port>\d+) '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<body_bytes>\d+) '
    r'(?P<request_bytes>\d+) '
    r'(?P<request_time>\d+\.\d{3}) '
    r'(?P<conn_id>\d+) '
    r'(?P<conn_requests>\d+) '
    r'"(?P<user_agent>[^"]*)"'
)
ESCAPE_RE = re.compile(rb"\\x([0-9A-Fa-f]{2})")
METHOD_RE = re.compile(r"[A-Z][A-Z0-9_-]*")

# Lý do bỏ qua một dòng
SKIP_EMPTY = "dong_trong"
SKIP_FORMAT = "sai_dinh_dang"         # không khớp 12 trường của định dạng nids
SKIP_VALUE = "gia_tri_sai"            # khớp định dạng nhưng IP, cổng hoặc mã trạng thái vô lý
SKIP_LAST_PARTIAL = "dong_cuoi_do_dang"  # dòng cuối không có ký tự xuống dòng (Nginx đang ghi)

# Điểm bất thường của dòng vẫn được giữ
NOTE_BAD_REQUEST = "dong_yeu_cau_khong_hop_le"  # dòng yêu cầu không phải "METHOD target HTTP/x"
NOTE_TS_BACKWARDS = "thoi_gian_giam"            # ts nhỏ hơn dòng trước (nhiều worker, đồng hồ bị chỉnh)


@dataclass(frozen=True)
class LogRecord:
    line_no: int              # số dòng trong file, bắt đầu từ 1
    ts_ns: int                # $msec: lúc yêu cầu kết thúc, nano giây từ epoch UTC
    client_ip: str            # IPv6 ở dạng rút gọn chuẩn như packets.py
    client_port: int | None   # None khi Nginx ghi "-" (kết nối qua unix socket)
    server_port: int
    request: str              # dòng yêu cầu đã giải mã \xHH; "" khi client không gửi gì đọc được
    method: str | None        # None khi dòng yêu cầu không hợp lệ
    target: str | None        # đường dẫn và query, giữ nguyên mã hóa %XX
    http_version: str | None  # "HTTP/1.1", ...; "HTTP/0.9" khi dòng yêu cầu chỉ có 2 phần
    status: int
    body_bytes: int
    request_bytes: int
    request_time_ms: int      # $request_time đổi ra mili giây (Nginx ghi độ phân giải ms)
    conn_id: int
    conn_requests: int        # yêu cầu thứ mấy trên kết nối này
    user_agent: str | None    # None khi Nginx ghi "-"

    @property
    def ts(self) -> float:
        return self.ts_ns / 1e9

    @property
    def start_ts_ns(self) -> int:
        """Thời điểm bắt đầu yêu cầu, xấp xỉ ts - request_time."""
        return self.ts_ns - self.request_time_ms * 10**6

    @property
    def request_time(self) -> float:
        return self.request_time_ms / 1000

    @property
    def valid_request(self) -> bool:
        return self.method is not None


@dataclass(frozen=True)
class LogParseResult:
    record: LogRecord | None
    reason: str | None = None
    detail: str = ""
    notes: tuple[str, ...] = ()


class _Skip(Exception):
    def __init__(self, reason, detail=""):
        super().__init__(reason, detail)
        self.reason = reason
        self.detail = detail


def unescape(value: str) -> str:
    """Giải mã \\xHH của Nginx; byte UTF-8 được ghép lại thành ký tự."""
    if "\\x" not in value:
        return value
    raw =ESCAPE_RE.sub(lambda m: bytes([int(m.group(1), 16)]), value.encode("latin-1"))
    return raw.decode("utf-8", errors="backslashreplace")


def split_request(request: str) -> tuple[str | None, str | None, str | None]:
    """Tách dòng yêu cầu thành (method, target, http_version); None nếu không hợp lệ."""
    parts = request.split(" ")
    if len(parts) == 3 and parts[2].startswith("HTTP/"):
        method, target, version = parts
    elif len(parts) == 2:
        method, target = parts
        version = "HTTP/0.9"
    else:
        return None, None, None
    if not METHOD_RE.fullmatch(method) or not target:
        return None, None, None
    return method, target, version


@lru_cache(maxsize=4096)
def _normalize_ip(text):
    # Lab chỉ có vài client nên nhớ kết quả, không phải phân tích lại ở mỗi dòng.
    return ip_address(text).compressed


def _ts_ns(text):
    sec, ms = text.split(".")
    return int(sec) * 10**9 + int(ms) * 10**6


def _ms(text):
    sec, ms = text.split(".")
    return int(sec) * 1000 + int(ms)


def _parse(line, line_no):
    m = LINE_RE.fullmatch(line)
    if m is None:
        raise _Skip(SKIP_FORMAT, f"{len(line.split())} trường")
    g = m.groupdict()
    try:
        client_ip = _normalize_ip(g["client_ip"])
    except ValueError:
        raise _Skip(SKIP_VALUE, "client_ip") from None
    client_port = None if g["client_port"] == "-" else int(g["client_port"])
    server_port = int(g["server_port"])
    if (client_port is not None and client_port > 65535) or not 0 < server_port <= 65535:
        raise _Skip(SKIP_VALUE, "cổng")
    status = int(g["status"])
    if not 100 <= status <= 599:
        raise _Skip(SKIP_VALUE, "status")
    request = "" if g["request"] == "-" else unescape(g["request"])
    method, target, version = split_request(request)
    user_agent = None if g["user_agent"] == "-" else unescape(g["user_agent"])
    return LogRecord(
        line_no, _ts_ns(g["ts"]), client_ip, client_port, server_port, request,
        method, target, version, status, int(g["body_bytes"]), int(g["request_bytes"]),
        _ms(g["request_time"]), int(g["conn_id"]), int(g["conn_requests"]), user_agent,
    )


def inspect_line(line: str, line_no: int = 0) -> LogParseResult:
    """Phân tích một dòng log (đã bỏ ký tự xuống dòng); ghi lý do nếu bỏ qua."""
    if not line.strip():
        return LogParseResult(None, SKIP_EMPTY)
    try:
        record = _parse(line, line_no)
    except _Skip as skip:
        return LogParseResult(None, skip.reason, skip.detail)
    notes = () if record.valid_request else (NOTE_BAD_REQUEST,)
    return LogParseResult(record, notes=notes)


def parse_line(line: str, line_no: int = 0) -> LogRecord | None:
    """Phân tích một dòng log; None nếu dòng không đúng định dạng nids."""
    return inspect_line(line, line_no).record


class LogStats:
    """Đếm dòng đọc được, dòng bỏ qua theo lý do và khoảng thời gian của log."""

    SAMPLES_PER_REASON = 3

    def __init__(self):
        self.total = 0
        self.kept = 0
        self.skipped = Counter()
        self.first_skipped = {}   # lý do -> số dòng đầu tiên
        self.samples = {}         # lý do -> vài dòng mẫu (cắt 200 ký tự) để xem lỗi
        self.notes = Counter()
        self.status = Counter()
        self.first_ts_ns = None
        self.last_ts_ns = None
        self._prev_ts_ns = None

    @property
    def skipped_total(self) -> int:
        return self.total - self.kept

    def add(self, line_no: int, line: str, result: LogParseResult):
        self.total += 1
        if result.record is None:
            self.skipped[result.reason] += 1
            self.first_skipped.setdefault(result.reason, line_no)
            samples = self.samples.setdefault(result.reason, [])
            if len(samples) < self.SAMPLES_PER_REASON and result.reason != SKIP_EMPTY:
                samples.append(line[:200])
            return
        rec = result.record
        self.kept += 1
        self.notes.update(result.notes)
        self.status[rec.status] += 1
        if self._prev_ts_ns is not None and rec.ts_ns < self._prev_ts_ns:
            self.notes[NOTE_TS_BACKWARDS] += 1
        self._prev_ts_ns = rec.ts_ns
        self.first_ts_ns = rec.ts_ns if self.first_ts_ns is None else min(self.first_ts_ns, rec.ts_ns)
        self.last_ts_ns = rec.ts_ns if self.last_ts_ns is None else max(self.last_ts_ns, rec.ts_ns)

    def as_dict(self) -> dict:
        return {
            "tong_dong": self.total,
            "doc_duoc": self.kept,
            "bo_qua": self.skipped_total,
            "bo_qua_theo_ly_do": dict(self.skipped.most_common()),
            "dong_dau_tien_bo_qua": self.first_skipped,
            "dong_mau_bo_qua": self.samples,
            "ghi_chu": dict(self.notes.most_common()),
            "theo_ma_trang_thai": {str(k): v for k, v in sorted(self.status.items())},
            "ts_dau_ns": self.first_ts_ns,
            "ts_cuoi_ns": self.last_ts_ns,
        }

    def summary_lines(self) -> list[str]:
        lines = [f"Tổng dòng: {self.total}; đọc được: {self.kept}; bỏ qua: {self.skipped_total}"]
        for reason, n in self.skipped.most_common():
            lines.append(f"  {reason}: {n} (dòng đầu tiên: {self.first_skipped[reason]})")
            for sample in self.samples.get(reason, []):
                lines.append(f"      {sample}")
        if self.notes:
            lines.append("Ghi chú: " + ", ".join(f"{k}={v}" for k, v in self.notes.most_common()))
        if self.status:
            lines.append("Theo mã trạng thái: " + ", ".join(
                f"{k}={v}" for k, v in sorted(self.status.items())))
        if self.first_ts_ns is not None:
            lines.append(f"Thời gian: {_format_ts(self.first_ts_ns)} -> {_format_ts(self.last_ts_ns)}")
        if self.total and not self.kept:
            lines.append(f"CẢNH BÁO: không dòng nào đúng định dạng '{LOG_FORMAT_NAME}';"
                         " kiểm tra log_format trên máy chủ dịch vụ")
        return lines


def _open(path):
    path = Path(path)
    if path.suffix == ".gz":
        return gzip.open(path, "rb")
    return path.open("rb")


def read_log(path, stats: LogStats | None = None):
    """Duyệt các dòng đọc được của một file access log (.log hoặc .gz đã xoay vòng)."""
    with _open(path) as f:
        for line_no, raw in enumerate(f, start=1):
            complete = raw.endswith(b"\n")
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            result = inspect_line(line, line_no)
            if result.record is None and not complete and line:
                result = LogParseResult(None, SKIP_LAST_PARTIAL)
            if stats is not None:
                stats.add(line_no, line, result)
            if result.record is not None:
                yield result.record


# Cột của bảng CSV. ts giữ đúng dạng $msec ("giây.mili giây") để đối chiếu được
# với dòng gốc; start_ts là ts - request_time, dùng khi ghép với flow.
CSV_COLUMNS = (
    "line_no", "ts", "start_ts", "client_ip", "client_port", "server_port",
    "request", "method", "target", "http_version", "status", "body_bytes",
    "request_bytes", "request_time_ms", "conn_id", "conn_requests", "user_agent",
    "valid_request",
)


def _msec(ts_ns):
    sec, rest = divmod(ts_ns, 10**9)
    return f"{sec}.{rest // 10**6:03d}"


def csv_row(rec: LogRecord) -> dict:
    """Một dòng của bảng CSV; ô trống khi giá trị là None."""
    row = {
        "line_no": rec.line_no, "ts": _msec(rec.ts_ns), "start_ts": _msec(rec.start_ts_ns),
        "client_ip": rec.client_ip, "client_port": rec.client_port,
        "server_port": rec.server_port, "request": rec.request, "method": rec.method,
        "target": rec.target, "http_version": rec.http_version, "status": rec.status,
        "body_bytes": rec.body_bytes, "request_bytes": rec.request_bytes,
        "request_time_ms": rec.request_time_ms, "conn_id": rec.conn_id,
        "conn_requests": rec.conn_requests, "user_agent": rec.user_agent,
        "valid_request": int(rec.valid_request),
    }
    return {col: "" if row[col] is None else row[col] for col in CSV_COLUMNS}


def write_csv(records, path) -> int:
    """Ghi các bản ghi ra CSV UTF-8; trả về số dòng đã ghi."""
    n = 0
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for rec in records:
            writer.writerow(csv_row(rec))
            n += 1
    return n


def _format_ts(ts_ns):
    sec, ns = divmod(ts_ns, 10**9)
    return datetime.fromtimestamp(sec, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{ns // 10**6:03d}Z"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Đọc access log Nginx định dạng nids và in tóm tắt."
    )
    parser.add_argument("file", help="đường dẫn access_nids.log (hoặc bản .gz)")
    parser.add_argument("--csv", help="ghi bảng dòng log ra file CSV")
    parser.add_argument("--stats", help="ghi thống kê dòng bỏ qua ra file JSON")
    parser.add_argument("-n", "--count", type=int, default=10,
                        help="số dòng đầu tiên được in (mặc định: %(default)s)")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    stats = LogStats()

    def shown(records):
        for rec in records:
            if stats.kept <= args.count:
                req = rec.request if len(rec.request) <= 60 else rec.request[:57] + "..."
                print(f"{rec.line_no:>6}  {_format_ts(rec.ts_ns)}  {rec.client_ip}:{rec.client_port}"
                      f" -> :{rec.server_port}  {req!r}  {rec.status}  {rec.request_time_ms} ms"
                      f"  conn={rec.conn_id}/{rec.conn_requests}")
            yield rec

    records = shown(read_log(args.file, stats))
    if args.csv:
        write_csv(records, args.csv)
    else:
        for _ in records:
            pass
    print()
    print("\n".join(stats.summary_lines()))
    if args.csv:
        print(f"Đã ghi CSV: {args.csv}")
    if args.stats:
        with open(args.stats, "w", encoding="utf-8") as f:
            json.dump(stats.as_dict(), f, ensure_ascii=False, indent=2)
        print(f"Đã ghi thống kê: {args.stats}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
