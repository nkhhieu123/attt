import gzip
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.service_log import (
    NOTE_BAD_REQUEST, NOTE_TS_BACKWARDS, SKIP_EMPTY, SKIP_FORMAT, SKIP_LAST_PARTIAL,
    SKIP_VALUE, LogStats, inspect_line, main, parse_line, read_log, split_request, unescape,
)

# Ghi từ Nginx 1.26.3 với log_format nids (docs/05_log_dich_vu.md), máy thử 127.0.0.1.
REAL_LINES = [
    r'1792581326.410 127.0.0.1 56911 18080 "GET /status HTTP/1.1" 200 3 57 0.000 1 1 "curl/8.5.0"',
    r'1792581326.718 127.0.0.1 56912 18080 "GET /index.html HTTP/1.1" 200 615 62 0.000 2 1 "Mozilla/5.0"',
    r'1792581326.718 127.0.0.1 56912 18080 "GET /status HTTP/1.1" 200 3 58 0.000 2 2 "Mozilla/5.0"',
    r'1792581326.718 127.0.0.1 56912 18080 "GET /khong-co HTTP/1.1" 404 153 60 0.000 2 3 "Mozilla/5.0"',
    r'1792581327.020 127.0.0.1 56913 18080 "GET /status HTTP/1.0" 200 3 24 0.000 3 1 "-"',
    r'1792581327.320 127.0.0.1 56914 18080 "GET /a%20b?q=\x22x\x22&t=\x5Cz HTTP/1.1" 404 153 86 0.000 4 1 "bot \x22quoted\x22 \x5C ti\xE1\xBA\xBFng Vi\xE1\xBB\x87t"',
    r'1792581327.621 127.0.0.1 56915 18080 "POST /status HTTP/1.1" 200 3 69 0.000 5 1 "py"',
    r'1792581328.224 127.0.0.1 56916 18080 "\x16\x03\x01\x00\xA5\x01\x00\x00\xA1\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" 400 157 0 0.301 6 1 "-"',
    r'1792581330.226 127.0.0.1 56917 18080 "GET /status HTT" 408 0 0 2.001 7 1 "-"',
    r'1792581331.529 127.0.0.1 56918 18080 "HELP" 400 157 0 0.303 8 1 "-"',
    r'1792581333.559 127.0.0.1 56919 18080 "GET /slow HTTP/1.1" 502 157 55 2.029 9 1 "curl/8.5.0"',
    r'1792581366.502 127.0.0.1 57646 18080 "GET /slow HTTP/1.1" 499 0 55 0.502 12 1 "curl/8.5.0"',
]
DOC_EXAMPLE = ('1791793800.123 192.168.50.41 51544 80 "GET /status HTTP/1.1" 200 15 78 '
               '0.002 1207 3 "curl/8.5.0"')


class LineTest(unittest.TestCase):
    def test_doc_example_all_fields(self):
        rec = parse_line(DOC_EXAMPLE, 7)
        self.assertEqual(rec.line_no, 7)
        self.assertEqual(rec.ts_ns, 1791793800_123_000_000)
        self.assertEqual((rec.client_ip, rec.client_port, rec.server_port),
                         ("192.168.50.41", 51544, 80))
        self.assertEqual((rec.method, rec.target, rec.http_version),
                         ("GET", "/status", "HTTP/1.1"))
        self.assertEqual((rec.status, rec.body_bytes, rec.request_bytes), (200, 15, 78))
        self.assertEqual((rec.request_time_ms, rec.conn_id, rec.conn_requests), (2, 1207, 3))
        self.assertEqual(rec.user_agent, "curl/8.5.0")
        self.assertEqual(rec.start_ts_ns, 1791793800_121_000_000)

    def test_keep_alive_requests_share_connection(self):
        recs = [parse_line(line) for line in REAL_LINES[1:4]]
        self.assertEqual({(r.conn_id, r.client_port) for r in recs}, {(2, 56912)})
        self.assertEqual([r.conn_requests for r in recs], [1, 2, 3])

    def test_escaped_quotes_backslash_and_utf8(self):
        rec = parse_line(REAL_LINES[5])
        self.assertEqual(rec.target, '/a%20b?q="x"&t=\\z')
        self.assertEqual(rec.user_agent, 'bot "quoted" \\ tiếng Việt')

    def test_missing_user_agent(self):
        self.assertIsNone(parse_line(REAL_LINES[4]).user_agent)

    def test_invalid_request_lines_are_kept_with_note(self):
        for line, status in ((REAL_LINES[7], 400), (REAL_LINES[8], 408), (REAL_LINES[9], 400)):
            result = inspect_line(line)
            self.assertEqual(result.record.status, status)
            self.assertIsNone(result.record.method)
            self.assertEqual(result.notes, (NOTE_BAD_REQUEST,))
        self.assertTrue(parse_line(REAL_LINES[7]).request.startswith("\x16\x03\x01"))

    def test_slow_and_aborted_requests(self):
        self.assertEqual((parse_line(REAL_LINES[10]).status, parse_line(REAL_LINES[10]).request_time_ms),
                         (502, 2029))
        self.assertEqual(parse_line(REAL_LINES[11]).status, 499)

    def test_ipv6_and_unix_socket(self):
        line = DOC_EXAMPLE.replace("192.168.50.41 51544", "fe80:0:0::1 -")
        rec = parse_line(line)
        self.assertEqual((rec.client_ip, rec.client_port), ("fe80::1", None))

    def test_skip_reasons(self):
        combined = ('192.168.50.41 - - [21/Oct/2026:10:00:00 +0700] "GET / HTTP/1.1" 200 15 '
                    '"-" "curl/8.5.0"')
        self.assertEqual(inspect_line(combined).reason, SKIP_FORMAT)
        self.assertEqual(inspect_line("   ").reason, SKIP_EMPTY)
        self.assertEqual(inspect_line(DOC_EXAMPLE.replace("192.168.50.41", "999.1.1.1")).reason,
                         SKIP_VALUE)
        self.assertEqual(inspect_line(DOC_EXAMPLE.replace(" 80 ", " 70000 ")).detail, "cổng")
        self.assertEqual(inspect_line(DOC_EXAMPLE.replace(" 200 ", " 999 ")).detail, "status")


class HelperTest(unittest.TestCase):
    def test_unescape(self):
        self.assertEqual(unescape(r"a\x22b\x5Cc"), 'a"b\\c')
        self.assertEqual(unescape(r"\xC3\xA9"), "é")
        self.assertEqual(unescape(r"\xA5"), "\\xa5")      # byte không phải UTF-8 giữ dạng \xHH

    def test_split_request(self):
        self.assertEqual(split_request("GET / HTTP/2.0"), ("GET", "/", "HTTP/2.0"))
        self.assertEqual(split_request("GET /"), ("GET", "/", "HTTP/0.9"))
        self.assertEqual(split_request(""), (None, None, None))
        self.assertEqual(split_request("get / HTTP/1.1"), (None, None, None))


class FileTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def write(self, name, text):
        path = self.dir / name
        path.write_bytes(text.encode("ascii"))
        return path

    def test_real_log_with_crlf(self):
        path = self.write("access_nids.log", "\r\n".join(REAL_LINES) + "\r\n")
        stats = LogStats()
        recs = list(read_log(path, stats))
        self.assertEqual(len(recs), 12)
        self.assertEqual([r.line_no for r in recs][:3], [1, 2, 3])
        self.assertEqual((stats.total, stats.kept, stats.skipped_total), (12, 12, 0))
        self.assertEqual(stats.notes[NOTE_BAD_REQUEST], 3)
        self.assertEqual(stats.status[200], 5)
        self.assertEqual(stats.first_ts_ns, 1792581326_410_000_000)

    def test_gzip_rotated_log(self):
        path = self.dir / "access_nids.log.1.gz"
        with gzip.open(path, "wb") as f:
            f.write(("\n".join(REAL_LINES[:3]) + "\n").encode())
        self.assertEqual(len(list(read_log(path))), 3)

    def test_bad_lines_and_partial_last_line(self):
        text = "\n".join([REAL_LINES[0], "rác", "", REAL_LINES[2], REAL_LINES[1]]) + "\n" + REAL_LINES[3][:40]
        path = self.dir / "mixed.log"
        path.write_bytes(text.encode("utf-8"))
        stats = LogStats()
        self.assertEqual(len(list(read_log(path, stats))), 3)
        self.assertEqual(dict(stats.skipped), {SKIP_FORMAT: 1, SKIP_EMPTY: 1, SKIP_LAST_PARTIAL: 1})
        self.assertEqual(stats.first_skipped[SKIP_FORMAT], 2)
        self.assertEqual(stats.samples[SKIP_FORMAT], ["rác"])
        self.assertEqual(stats.notes[NOTE_TS_BACKWARDS], 0)   # dòng 4 và 5 cùng ts

    def test_timestamp_going_backwards(self):
        path = self.write("back.log", "\n".join([REAL_LINES[4], REAL_LINES[0]]) + "\n")
        stats = LogStats()
        list(read_log(path, stats))
        self.assertEqual(stats.notes[NOTE_TS_BACKWARDS], 1)

    def test_cli(self):
        path = self.write("access_nids.log", "\n".join(REAL_LINES) + "\nxyz\n")
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main([str(path), "-n", "2"]), 0)
        text = out.getvalue()
        self.assertIn("Tổng dòng: 13; đọc được: 12; bỏ qua: 1", text)
        self.assertIn("sai_dinh_dang: 1 (dòng đầu tiên: 13)", text)
        self.assertIn("127.0.0.1:56911 -> :18080", text)

    def test_wrong_format_warning(self):
        path = self.write("combined.log", '1.2.3.4 - - [x] "GET / HTTP/1.1" 200 1 "-" "-"\n')
        stats = LogStats()
        list(read_log(path, stats))
        self.assertIn("CẢNH BÁO: không dòng nào đúng định dạng 'nids'", "\n".join(stats.summary_lines()))


if __name__ == "__main__":
    unittest.main()
