import csv
import io
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids import scope
from nids.alerts import CSV_COLUMNS, Alert, AlertSink, format_line


def make(module, label, **kw):
    return Alert(module, label, window_start=1000.0, window_end=1010.0, **kw)


class ScopeTest(unittest.TestCase):
    def test_three_modules_with_labels(self):
        self.assertEqual(len(scope.MODULES), 3)
        self.assertEqual(set(scope.LABELS), set(scope.MODULES))
        self.assertEqual(scope.CLASSIFIER_LABELS, ("benign", "port_scan", "dos"))
        self.assertEqual([s.name for s in scope.MODULE_SPECS], list(scope.MODULES))

    def test_first_version_has_no_dashboard(self):
        self.assertEqual(scope.OUTPUT_CHANNELS, ("terminal", "csv"))


class AlertTest(unittest.TestCase):
    def test_rejects_unknown_module_and_label(self):
        with self.assertRaises(ValueError):
            make("dashboard", "anomaly")
        with self.assertRaises(ValueError):
            make(scope.MODULE_ANOMALY, "dos")
        with self.assertRaises(ValueError):
            Alert(scope.MODULE_ANOMALY, "anomaly", window_start=10, window_end=5)

    def test_is_alert(self):
        self.assertTrue(make(scope.MODULE_CLASSIFIER, "port_scan").is_alert)
        self.assertFalse(make(scope.MODULE_CLASSIFIER, "benign").is_alert)
        self.assertFalse(make(scope.MODULE_BOTNET, "none").is_alert)

    def test_format_line(self):
        line = format_line(make(
            scope.MODULE_ANOMALY, "anomaly", src_ip="192.168.50.20",
            dst_ip="192.168.50.30", score=42.7, threshold=18.3, run_id="R01",
        ))
        self.assertIn("[anomaly] | ANOMALY", line)
        self.assertIn("192.168.50.20 -> 192.168.50.30", line)
        self.assertIn("score=42.7 (ngưỡng 18.3)", line)
        self.assertIn("run=R01", line)


class SinkTest(unittest.TestCase):
    def read(self, path):
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def test_writes_terminal_and_csv(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sub" / "alerts.csv"
            out = io.StringIO()
            with AlertSink(path, stream=out) as sink:
                self.assertTrue(sink.emit(make(scope.MODULE_CLASSIFIER, "dos", score=0.9)))
                self.assertFalse(sink.emit(make(scope.MODULE_CLASSIFIER, "benign")))
            rows = self.read(path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(list(rows[0]), CSV_COLUMNS)
            self.assertEqual(rows[0]["label"], "dos")
            self.assertEqual(rows[0]["window_start"], "1970-01-01T00:16:40.000Z")
            self.assertEqual(rows[0]["threshold"], "")
            self.assertEqual(len(out.getvalue().splitlines()), 1)

    def test_append_keeps_single_header(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.csv"
            for _ in range(2):
                with AlertSink(path, stream=io.StringIO()) as sink:
                    sink.emit(make(scope.MODULE_ANOMALY, "anomaly"))
            self.assertEqual(len(self.read(path)), 2)
            self.assertEqual(path.read_text(encoding="utf-8").count("module,label"), 1)

    def test_log_all_stores_normal_but_keeps_terminal_quiet(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "pred.csv"
            out = io.StringIO()
            with AlertSink(path, stream=out, log_all=True) as sink:
                sink.emit(make(scope.MODULE_ANOMALY, "normal"))
            self.assertEqual(len(self.read(path)), 1)
            self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
