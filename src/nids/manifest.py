"""Đọc manifest dữ liệu từ config/data_manifest.csv (C02-T05)."""

import csv
from pathlib import Path

from .config import PROJECT_ROOT
from .scope import LABELS, MODULES

DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "data_manifest.csv"

COLUMNS = (
    "id", "nguon", "bai_toan", "file", "dinh_dang", "thoi_gian",
    "nhan_goc", "nhan_do_an", "muc_dich", "dung_luong", "trang_thai", "ghi_chu",
)
REQUIRED = ("id", "nguon", "bai_toan", "file", "dinh_dang", "muc_dich", "trang_thai")
# Cột chứa nhiều giá trị, ngăn cách bằng dấu chấm phẩy.
LIST_COLUMNS = ("bai_toan", "nhan_do_an", "muc_dich")

REFERENCE = "doi_chieu"  # dữ liệu chỉ để đối chiếu, không vào mô hình
PROBLEMS = MODULES + (REFERENCE,)
PURPOSES = ("train", "validation", "test", REFERENCE)
STATUSES = ("chua_tai", "da_kiem_tra_may_chu", "da_tai_thu", "chua_thu")
PROJECT_LABELS = frozenset(label for labels in LABELS.values() for label in labels)


def load_manifest(path=None) -> list:
    """Trả về danh sách dict, mỗi dict là một dòng của manifest."""
    path = Path(path) if path else DEFAULT_MANIFEST
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise ValueError(f"{path}: cột phải là {COLUMNS}, nhận {reader.fieldnames}")
        rows = list(reader)
    seen = set()
    for row in rows:
        _validate(row, path)
        if row["id"] in seen:
            raise ValueError(f"{path}: trùng id {row['id']}")
        seen.add(row["id"])
        for col in LIST_COLUMNS:
            row[col] = _split(row[col])
    return rows


def entries_for(problem, rows=None) -> list:
    """Các dòng manifest phục vụ một bài toán (tên module hoặc ``doi_chieu``)."""
    rows = load_manifest() if rows is None else rows
    return [row for row in rows if problem in row["bai_toan"]]


def _split(value):
    return [item.strip() for item in value.split(";") if item.strip()]


def _validate(row, path):
    where = f"{path}: dòng {row.get('id') or '?'}"
    for col in REQUIRED:
        if not row[col].strip():
            raise ValueError(f"{where}: thiếu {col}")
    _check(_split(row["bai_toan"]), PROBLEMS, "bai_toan", where)
    _check(_split(row["muc_dich"]), PURPOSES, "muc_dich", where)
    _check(_split(row["nhan_do_an"]), PROJECT_LABELS, "nhan_do_an", where)
    _check([row["trang_thai"]], STATUSES, "trang_thai", where)


def _check(values, allowed, col, where):
    unknown = [v for v in values if v not in allowed]
    if unknown:
        raise ValueError(f"{where}: {col} không hợp lệ: {unknown}")
