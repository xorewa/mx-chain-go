"""Synthetic diagnostic CLI reports unavailable tool inputs without making up counts."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import producer
import report


class ProducerUnavailableTests(unittest.TestCase):
    def test_script_reports_unavailable_compiler_and_common_metadata(self):
        subject = 'b' * 40
        node = [report.NODE + f'/synthetic_{i:02d}' for i in range(38)]
        common = report.COMMON + '/synthetic_common'
        roster = {'schema': 'standard-token-provisional-roster-v1',
                  'node': node, 'common': [common]}
        known, unavailable = node[:2]
        key = (known + '/example.go', (1, 1), (1, 4))
        missing_key = (unavailable + '/example.go', (1, 1), (1, 4))

        def sha(raw):
            return hashlib.sha256(raw).hexdigest()

        def blob(raw):
            return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            root, cli, output = temp / 'node', temp / 'cli', temp / 'out'
            root.mkdir()
            cli.mkdir()
            (cli / 'roster.json').write_text(json.dumps(roster))
            # Execute the exact script source with a synthetic __file__ so its
            # ordinary command-line entry reads only synthetic roster inputs.
            script = Path(producer.__file__).resolve()
            script_bytes = script.read_bytes()
            source = cli / 'producer.py'
            source.write_bytes(script_bytes)
            verifier = cli.parent / 'common-direct' / 'diagnostic.py'
            verifier.parent.mkdir()
            verifier.write_text(
                'import subprocess\n'
                'def verify_module(root, work):\n'
                '    return subprocess.run(("synthetic-common-tool",), cwd=root, check=True).stdout\n'
            )
            locks = {'go.mod': b'synthetic module\n', 'go.sum': b'synthetic lock\n'}
            tracked = {name: blob(raw) for name, raw in locks.items()}
            for name, raw in locks.items():
                (root / name).write_bytes(raw)
            leaf = root / 'synthetic_00'
            leaf.mkdir()
            raw_source = b'synthetic source label\n'
            (leaf / 'example.go').write_bytes(raw_source)
            tracked['synthetic_00/example.go'] = blob(raw_source)
            direct = root / '.github/coverage/ordinary'
            for name in ('node-direct-r25.json', 'common-direct/census.json',
                         'node-direct-race/selectors-r28.json'):
                target = direct / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('{"functions":[]}')
            normal, race_input, race_report = (temp / name for name in
                                               ('normal', 'race-in', 'race-report'))
            for p in (normal, race_input, race_report):
                p.mkdir()

            listed, compiled, formatted, common_calls = [], [], [], []
            compiler_modes = {}
            marker = 'synthetic tool message'
            profile = f'mode: atomic\n{key[0]}:1.1,1.4 2 0\n'.encode()

            def fake_run(args, **kwargs):
                self.assertEqual(root, kwargs['cwd'])
                self.assertTrue(kwargs['check'])
                if args == ('synthetic-common-tool',):
                    common_calls.append(args)
                    raise FileNotFoundError(marker)
                if args == ('git', 'rev-parse', 'HEAD'):
                    return SimpleNamespace(stdout=(subject + '\n').encode())
                if args == ('go', 'version'):
                    return SimpleNamespace(stdout=b'go version go1.26.2 linux/amd64\n')
                if args == ('git', 'ls-tree', '-rz', 'HEAD'):
                    body = ''.join(f'100644 blob {v}\t{k}\0' for k, v in sorted(tracked.items()))
                    return SimpleNamespace(stdout=body.encode())
                if args[:3] == ('go', 'list', '-json'):
                    mode = 'race' if args[3] == '-race' else 'normal'
                    pkg = args[-1]
                    self.assertEqual(('-race', pkg) if mode == 'race' else (pkg,), args[3:])
                    self.assertIn(pkg, node)
                    listed.append((mode, pkg))
                    if pkg != known:
                        raise subprocess.CalledProcessError(1, args, stderr=marker.encode())
                    entry = {'ImportPath': known, 'Module': {'Path': report.NODE},
                             'Dir': str(leaf), 'GoFiles': ['example.go'], 'Name': 'synthetic_00'}
                    return SimpleNamespace(stdout=json.dumps(entry).encode())
                if args[:3] == ('go', 'tool', 'cover'):
                    cfg = json.loads(Path(args[4]).read_text())
                    self.assertEqual(known, cfg['PkgPath'])
                    self.assertEqual(str(leaf / 'example.go'), args[-1])
                    meta = Path(cfg['EmitMetaFile'])
                    mode = meta.parent.parent.name.split('-')[0]
                    self.assertIn(mode, ('normal', 'race'))
                    meta.write_bytes(b'synthetic compiler marker')
                    compiler_modes[meta.parent] = mode
                    compiled.append(mode)
                    return SimpleNamespace(stdout=b'')
                if args[:4] == ('go', 'tool', 'covdata', 'textfmt'):
                    mode = compiler_modes[Path(args[4].removeprefix('-i='))]
                    Path(args[5].removeprefix('-o=')).write_bytes(profile)
                    formatted.append(mode)
                    return SimpleNamespace(stdout=b'')
                self.fail('unexpected synthetic command')

            def reviewed(checkout, manifest, manifest_sha, supplied_roster):
                self.assertEqual(root, checkout)
                self.assertEqual(roster, supplied_roster)
                self.assertEqual(sha((output / 'compiler-manifest.json').read_bytes()), manifest_sha)
                self.assertFalse(manifest['common_module_verified'])
                return {'status': 'NOT_EVALUATED', 'full_ordinary_only_denominator': None,
                        'compiler_manifest_sha256': manifest_sha}

            argv = ['producer.py', '--checkout', str(root), '--subject', subject,
                    '--output', str(output), '--normal-dir', str(normal),
                    '--race-input', str(race_input), '--race-report', str(race_report)]
            with patch.object(sys, 'argv', argv), \
                 patch.object(subprocess, 'run', side_effect=fake_run), \
                 patch.object(report, 'normal_node', return_value=(
                     {key: (2, True), missing_key: (5, True)}, sha(b'normal'))), \
                 patch.object(report, 'race_node', return_value=(
                     {key: (2, False), missing_key: (5, True)}, sha(b'race'))), \
                 patch.object(producer.attribution, 'build', side_effect=reviewed) as review:
                exec(compile(script_bytes, str(script), 'exec'),
                     {'__name__': '__main__', '__file__': str(source)})

            self.assertEqual([('synthetic-common-tool',)], common_calls)
            self.assertEqual([(m, p) for m in ('normal', 'race') for p in node], listed)
            self.assertEqual(['normal', 'race'], compiled)
            self.assertEqual(compiled, formatted)
            self.assertEqual(1, review.call_count)
            self.assertEqual({'compiler-manifest.json', 'compiler-report.json', 'reviewed-attribution.json'},
                             {p.name for p in output.iterdir()})
            manifest_bytes = (output / 'compiler-manifest.json').read_bytes()
            manifest = json.loads(manifest_bytes)
            metrics = json.loads((output / 'compiler-report.json').read_bytes())
            reviewed_doc = json.loads((output / 'reviewed-attribution.json').read_bytes())
            self.assertEqual(subject, manifest['subject'])
            self.assertFalse(manifest['common_module_verified'])
            self.assertEqual('source_or_tool_input_unavailable', manifest['common_module_reason'])
            self.assertEqual('NOT_EVALUATED', metrics['status'])
            self.assertIsNone(metrics['full_standard_token'])
            self.assertEqual('NOT_EVALUATED', reviewed_doc['status'])
            self.assertIsNone(reviewed_doc['full_ordinary_only_denominator'])
            self.assertEqual(sha(manifest_bytes), metrics['compiler_manifest_sha256'])
            self.assertEqual(sha(manifest_bytes), reviewed_doc['compiler_manifest_sha256'])
            self.assertNotIn(marker, manifest_bytes.decode())
            self.assertNotIn(marker, (output / 'compiler-report.json').read_text())
            for mode, covered in (('normal', 2), ('race', 0)):
                with self.subTest(mode=mode):
                    rows = manifest['mode'][mode]
                    self.assertEqual(set(node + [common]), set(rows))
                    self.assertEqual({'status': 'metadata_present', 'sources': {key[0]: sha(raw_source)},
                                      'compiler_profile_sha256': sha(profile),
                                      'blocks': [[key[0], 1, 1, 1, 4, 2]]}, rows[known])
                    self.assertEqual({'status': 'unavailable', 'reason': 'common_module_unverified'}, rows[common])
                    for pkg in node[1:]:
                        self.assertEqual({'status': 'unavailable', 'reason': 'source_or_tool_input_unavailable'},
                                         rows[pkg])
                    measured = metrics['mode'][mode]
                    self.assertEqual({'covered': covered, 'total': 2}, measured[known]['observed_statements'])
                    for pkg in node[1:] + [common]:
                        self.assertEqual('census_unavailable', measured[pkg]['status'])
                        self.assertEqual('census_unavailable', measured[pkg]['observation_status'])
                        for field in ('compiler_blocks', 'observed_blocks', 'missing_blocks',
                                      'expected_statements', 'observed_statements',
                                      'missing_statements', 'complete_subset_statements'):
                            self.assertIsNone(measured[pkg][field])
                    total = metrics['aggregate'][mode]['roster']
                    self.assertEqual((39, 1, 1, 38), tuple(total[k] for k in
                        ('packages_requested', 'packages_with_census', 'packages_complete', 'packages_census_unavailable')))
                    self.assertEqual(1, total['known_compiler_blocks'])
                    self.assertEqual(2, total['known_expected_statements'])
                    self.assertEqual({'covered': covered, 'total': 2}, total['observed_statements'])
                    self.assertIsNone(total['complete_statements'])
                    self.assertEqual({'status': 'not_supplied', 'profile_sha256': None},
                                     metrics['inputs'][mode + '_common'])
