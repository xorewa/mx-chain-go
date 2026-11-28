"""Detached Common wrapper import and directory forwarding, without external tools."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import producer


class CommonRootSyntheticTests(unittest.TestCase):
    def test_common_root_loads_sibling_verifier_and_returns_mocked_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            here = base / 'standard-token'
            sibling = base / 'common-direct'
            root = base / 'synthetic-node'
            work = base / 'synthetic-work'
            module = base / 'synthetic-common'
            for directory in (here, sibling, root, work, module):
                directory.mkdir()
            label = module / 'ordinary-label.txt'
            label.write_bytes(b'synthetic module directory label\n')

            # Exercise the actual wrapper's dynamic sibling import; its
            # downstream verifier is a temporary stand-in, not the real
            # module verification tool or an actual Go/Git checkout.
            verifier = sibling / 'diagnostic.py'
            verifier.write_text(
                'from pathlib import Path\n'
                'import subprocess\n\n'
                'def verify_module(root, work):\n'
                '    result = subprocess.run(("synthetic-module-directory", str(work)),\n'
                '                            cwd=root, check=True, capture_output=True)\n'
                '    return Path(result.stdout.decode().strip()).resolve()\n',
                encoding='utf-8',
            )
            before = verifier.read_bytes()
            argv = ('synthetic-module-directory', str(work))
            response = subprocess.CompletedProcess(argv, 0, stdout=(str(module) + '\n').encode(), stderr=b'')
            with patch.object(producer, 'HERE', here), \
                    patch.object(producer.subprocess, 'run', return_value=response) as tool:
                actual = producer.common_root(root, work)
            tool.assert_called_once_with(argv, cwd=root, check=True, capture_output=True)
            self.assertEqual(module.resolve(), actual)
            self.assertEqual(b'synthetic module directory label\n', label.read_bytes())
            self.assertEqual(before, verifier.read_bytes())
            self.assertEqual([], list(root.iterdir()))
            self.assertEqual([], list(work.iterdir()))
