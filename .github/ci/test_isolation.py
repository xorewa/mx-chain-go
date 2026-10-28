import contextlib
import io
import subprocess
import unittest
from unittest.mock import patch

from check_isolation import main


class IsolationPreflightTests(unittest.TestCase):
    def probe(self, result=None, error=None):
        out, err = io.StringIO(), io.StringIO()
        with patch("check_isolation.subprocess.run", return_value=result, side_effect=error) as run:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main()
        self.assertEqual(run.call_count, 1)
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["unshare", "--user", "--map-root-user", "--net", "--"])
        self.assertNotIn("go", command)
        return code, out.getvalue(), err.getvalue()

    def test_available_namespace(self):
        code, out, err = self.probe(subprocess.CompletedProcess([], 0, '[{"ifname":"lo","flags":["UP","LOOPBACK"]}]', ''))
        self.assertEqual(code, 0)
        self.assertIn("loopback-only", out)
        self.assertNotIn("::error", err)

    def test_denied_missing_or_invalid_namespace_is_infrastructure_failure(self):
        for result in [subprocess.CompletedProcess([], 1, '', 'unshare: Operation not permitted'),
                       subprocess.CompletedProcess([], 0, 'not JSON', ''),
                       subprocess.CompletedProcess([], 0, '[]', ''),
                       subprocess.CompletedProcess([], 0, '[{"ifname":"eth0","flags":["UP"]}]', ''),
                       subprocess.CompletedProcess([], 0, '[{"ifname":"lo","flags":[]}]', '')]:
            with self.subTest(result=result):
                code, out, err = self.probe(result)
                self.assertEqual(code, 1)
                self.assertIn("::error title=CI network isolation unavailable::", err)
                self.assertIn("No tests were started", err)
        self.assertEqual(self.probe(error=FileNotFoundError("unshare"))[0], 1)


if __name__ == "__main__":
    unittest.main()
