"""Đối chiếu bảng CSV của access log với file log gốc (C03-T06).

Với mỗi dòng được chọn, đọc lại dòng gốc theo số dòng, tách 12 trường bằng
cách duyệt từng ký tự (không dùng regex của service_log) và giải mã \\xHH bằng
codec có sẵn của Python, rồi so với giá trị trong CSV. Hai cách đọc độc lập cho
cùng kết quả thì bảng CSV phản ánh đúng dòng gốc.

Dòng được chọn gồm: dòng đầu, dòng cuối, một dòng cho mỗi mã trạng thái, các
dòng có yêu cầu không hợp lệ, và một số dòng ngẫu nhiên (seed cố định). Dùng
--all để đối chiếu mọi dòng.

    python -m nids.log_compare access_nids.log output/log.csv -k 20
"""

import argparse
import csv
import gzip
import random
import sys
from decimal import Decimal
from ipaddress import ip_address
from pathlib import Path

# Thứ tự trường của log_format nids (docs/05_log_dich_vu.md, mục 3)
NIDS_FIELDS = (
    "ts", "client_ip", "client_port", "server_port", "request", "status",
    "body_bytes", "request_bytes", "request_time", "conn_id", "conn_requests",
    "user_agent",
)
QUOTED_FIELDS = (4, 11)


def tokenize(line: str) -> list[str] | None:
    """Tách dòng nids thành 12 chuỗi thô; trường trong ngoặc kép bỏ ngoặc."""
    tokens = []
    i = 0
    n = len(line)
    while i < n:
        if line[i] == '"':
            end = line.find('"', i + 1)    # Nginx đã đổi " bên trong thành \x22
            if end < 0:
                return None
            tokens.append(line[i + 1:end])
            i = end + 1
        else:
            end = line.find(" ", i)
            end = n if end < 0 else end
            tokens.append(line[i:end])
            i = end
        if i < n:
            if line[i] != " ":
                return None
            i += 1
    if len(tokens) != len(NIDS_FIELDS):
        return None
    return tokens


def decode_nginx(value: str) -> str:
    """Giải mã \\xHH bằng codec unicode_escape rồi ghép byte UTF-8."""
    as_bytes = value.encode("ascii", "backslashreplace").decode("unicode_escape").encode("latin-1")
    return as_bytes.decode("utf-8", errors="backslashreplace")


def expected_row(tokens: list[str]) -> dict:
    """Giá trị CSV mong đợi, tính thẳng từ các chuỗi của dòng gốc."""
    t = dict(zip(NIDS_FIELDS, tokens))
    request = "" if t["request"] == "-" else decode_nginx(t["request"])
    ts = Decimal(t["ts"])
    rt = Decimal(t["request_time"])
    return {
        "ts": t["ts"],
        "start_ts": f"{ts - rt:.3f}",
        "client_ip": str(ip_address(t["client_ip"])),
        "client_port": "" if t["client_port"] == "-" else t["client_port"],
        "server_port": t["server_port"],
        "request": request,
        "status": t["status"],
        "body_bytes": t["body_bytes"],
        "request_bytes": t["request_bytes"],
        "request_time_ms": str(int(rt * 1000)),
        "conn_id": t["conn_id"],
        "conn_requests": t["conn_requests"],
        "user_agent": "" if t["user_agent"] == "-" else decode_nginx(t["user_agent"]),
    }


def compare_row(line: str, row: dict) -> list[str]:
    """Danh sách trường lệch giữa dòng gốc và dòng CSV; rỗng nếu khớp."""
    tokens = tokenize(line)
    if tokens is None:
        return ["không tách được dòng gốc"]
    exp = expected_row(tokens)
    diffs = [f"{k}: gốc={v!r} csv={row.get(k)!r}" for k, v in exp.items() if row.get(k) != v]
    # method/target/http_version phải ghép lại đúng dòng yêu cầu
    if row.get("valid_request") == "1":
        parts = [row["method"], row["target"]]
        if row["http_version"] != "HTTP/0.9":
            parts.append(row["http_version"])
        if " ".join(parts) != exp["request"]:
            diffs.append(f"method/target/http_version không ghép lại được {exp['request']!r}")
    elif row.get("method") or row.get("target"):
        diffs.append("dòng không hợp lệ nhưng có method/target")
    return diffs


def _read_lines(path):
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as f:
        return [raw.decode("utf-8", errors="replace").rstrip("\r\n") for raw in f]


def _read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def choose_rows(rows, k, seed):
    """Chọn dòng đối chiếu: đầu, cuối, mỗi mã trạng thái, yêu cầu không hợp lệ, ngẫu nhiên."""
    if not rows:
        return []
    picked = {0, len(rows) - 1}
    seen_status = set()
    invalid = 0
    for i, row in enumerate(rows):
        if row["status"] not in seen_status:
            seen_status.add(row["status"])
            picked.add(i)
        if row["valid_request"] == "0" and invalid < 5:
            picked.add(i)
            invalid += 1
    rest = [i for i in range(len(rows)) if i not in picked]
    picked.update(random.Random(seed).sample(rest, min(k, len(rest))))
    return [rows[i] for i in sorted(picked)]


def compare_files(log_path, csv_path, k=20, seed=42, check_all=False):
    """Đối chiếu CSV với log gốc; trả về (số dòng đã so, danh sách lỗi, dòng đã chọn)."""
    lines = _read_lines(log_path)
    rows = _read_csv(csv_path)
    problems = []
    numbers = [int(r["line_no"]) for r in rows]
    if numbers != sorted(set(numbers)):
        problems.append("line_no trong CSV không tăng dần hoặc bị trùng")
    if numbers and numbers[-1] > len(lines):
        problems.append(f"CSV có line_no {numbers[-1]} nhưng file gốc chỉ có {len(lines)} dòng")
    # Dòng gốc không có trong CSV phải là dòng không đọc được, không phải dòng hợp lệ bị sót.
    in_csv = set(numbers)
    for no, line in enumerate(lines, start=1):
        if no not in in_csv and tokenize(line) is not None:
            problems.append(f"dòng {no} tách được 12 trường nhưng không có trong CSV")
    chosen = rows if check_all else choose_rows(rows, k, seed)
    for row in chosen:
        no = int(row["line_no"])
        if no > len(lines):
            continue
        for diff in compare_row(lines[no - 1], row):
            problems.append(f"dòng {no}: {diff}")
    return len(chosen), problems, chosen, lines


def main(argv=None):
    parser = argparse.ArgumentParser(description="Đối chiếu bảng CSV của access log với file gốc.")
    parser.add_argument("log", help="file access log gốc")
    parser.add_argument("csv", help="file CSV xuất bởi python -m nids.service_log --csv")
    parser.add_argument("-k", type=int, default=20, help="số dòng ngẫu nhiên thêm vào mẫu")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--all", action="store_true", help="đối chiếu mọi dòng")
    parser.add_argument("--show", type=int, default=5,
                        help="số dòng mẫu in cạnh nhau gốc/CSV (mặc định: %(default)s)")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    n, problems, chosen, lines = compare_files(args.log, args.csv, args.k, args.seed, args.all)
    for row in chosen[:args.show]:
        no = int(row["line_no"])
        print(f"--- dòng {no}")
        print(f"gốc: {lines[no - 1][:160]}")
        print("csv: " + " | ".join(f"{k}={row[k]!r}" for k in (
            "ts", "client_ip", "client_port", "server_port", "request", "status",
            "body_bytes", "request_bytes", "request_time_ms", "conn_id", "conn_requests",
            "user_agent")))
    print()
    print(f"Dòng gốc: {len(lines)}; dòng CSV: {len(_read_csv(args.csv))}; đã đối chiếu: {n}")
    if problems:
        print(f"LỆCH: {len(problems)}")
        for p in problems[:20]:
            print("  " + p)
        return 1
    print("Khớp toàn bộ các dòng đã đối chiếu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
