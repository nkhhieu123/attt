import csv
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.log_compare import choose_rows, compare_files, decode_nginx, main, tokenize
from nids.service_log import CSV_COLUMNS, csv_row, main as log_main, parse_line, read_log, write_csv
from test_service_log import REAL_LINES


class TokenizeTest(unittest.TestCase):
    def test_real_lines_have_12_tokens(self):
        for line in REAL_LINES:
            self.assertEqual(len(tokenize(line)), 12, line)

    def test_quoted_fields(self):
        tokens = tokenize(REAL_LINES[5])
        self.assertEqual(tokens[4], r"GET /a%20b?q=\x22x\x22&t=\x5Cz HTTP/1.1")
        self.assertEqual(decode_nginx(tokens[11]), 'bot "quoted" \\ tiếng Việt')

    def test_bad_lines(self):
        self.assertIsNone(tokenize('1.000 1.2.3.4 1 80 "GET / HTTP/1.1'))   # thiếu ngoặc đóng
        self.assertIsNone(tokenize("a b c"))
        self.assertIsNone(tokenize(REAL_LINES[0] + " thừa"))


class CsvRowTest(unittest.TestCase):
    def test_columns_and_values(self):
        row = csv_row(parse_line(REAL_LINES[10], 11))
        self.assertEqual(tuple(row), CSV_COLUMNS)
        self.assertEqual((row["ts"], row["start_ts"]), ("1792581333.559", "1792581331.530"))
        self.assertEqual((row["request_time_ms"], row["valid_request"]), (2029, 1))

    def test_empty_cells_for_none(self):
        row = csv_row(parse_line(REAL_LINES[9]))       # "HELP", không có UA
        self.assertEqual((row["method"], row["target"], row["user_agent"]), ("", "", ""))
        self.assertEqual(row["valid_request"], 0)


class FileTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.log = self.dir / "access_nids.log"
        self.log.write_bytes(("\r\n".join(REAL_LINES[:6] + ["dòng hỏng"] + REAL_LINES[6:]) + "\r\n")
                             .encode("utf-8"))
        self.csv = self.dir / "log.csv"
        self.assertEqual(write_csv(read_log(self.log), self.csv), 12)

    def rows(self):
        with open(self.csv, encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))

    def write_rows(self, rows):
        with open(self.csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)

    def test_csv_round_trip_keeps_control_characters(self):
        rows = self.rows()
        self.assertEqual(len(rows), 12)
        self.assertEqual([r["line_no"] for r in rows[5:8]], ["6", "8", "9"])   # dòng 7 hỏng
        self.assertTrue(rows[7]["request"].startswith("\x16\x03\x01"))    # dòng 9: byte TLS

    def test_all_lines_match(self):
        n, problems, _, _ = compare_files(self.log, self.csv, check_all=True)
        self.assertEqual((n, problems), (12, []))

    def test_detects_changed_cell(self):
        rows = self.rows()
        rows[2]["client_port"] = "1"
        rows[5]["user_agent"] = "khác"
        rows[8]["request_time_ms"] = "2000"
        self.write_rows(rows)
        _, problems, _, _ = compare_files(self.log, self.csv, check_all=True)
        self.assertEqual(len(problems), 3)
        self.assertTrue(problems[0].startswith("dòng 3: client_port"))

    def test_detects_shifted_or_missing_rows(self):
        rows = self.rows()
        rows[0]["line_no"] = "2"                       # lệch số dòng
        self.write_rows(rows)
        _, problems, _, _ = compare_files(self.log, self.csv, check_all=True)
        self.assertTrue(any("không tăng dần" in p for p in problems))
        self.write_rows(self.rows()[1:])               # mất dòng 1
        _, problems, _, _ = compare_files(self.log, self.csv, check_all=True)
        self.assertIn("dòng 1 tách được 12 trường nhưng không có trong CSV", problems)

    def test_detects_wrong_split_of_request(self):
        rows = self.rows()
        rows[0]["target"] = "/khac"
        self.write_rows(rows)
        _, problems, _, _ = compare_files(self.log, self.csv, check_all=True)
        self.assertEqual(len(problems), 1)
        self.assertIn("không ghép lại được", problems[0])

    def test_sample_covers_first_last_status_and_invalid(self):
        rows = self.rows()
        chosen = {r["line_no"] for r in choose_rows(rows, k=0, seed=1)}
        self.assertTrue({"1", "13"} <= chosen)
        self.assertTrue({"9", "10", "11"} <= chosen)   # 3 yêu cầu không hợp lệ (dòng 7 hỏng)
        self.assertEqual({r["status"] for r in rows}, {r["status"] for r in rows if r["line_no"] in chosen})

    def test_cli(self):
        out_csv = self.dir / "cli.csv"
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(log_main([str(self.log), "-n", "0", "--csv", str(out_csv)]), 0)
        self.assertIn("Đã ghi CSV", out.getvalue())
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main([str(self.log), str(out_csv), "-k", "3"]), 0)
        self.assertIn("Khớp toàn bộ các dòng đã đối chiếu.", out.getvalue())
        self.assertIn("--- dòng 1", out.getvalue())
        rows = self.rows()
        rows[0]["status"] = "500"
        self.write_rows(rows)
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main([str(self.log), str(self.csv)]), 1)
        self.assertIn("LỆCH: 1", out.getvalue())


if __name__ == "__main__":
    unittest.main()
