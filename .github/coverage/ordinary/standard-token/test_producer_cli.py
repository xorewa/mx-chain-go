"""Nominal compiler-report CLI with synthetic package and tool boundaries only."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import producer
import report


class ProducerCliTests(unittest.TestCase):
    def test_cli_writes_bound_mode_separated_synthetic_compiler_census(self):
        subject = 'a' * 40
        node_labels = [f'synthetic_{i:02d}' for i in range(38)]
        common_label = 'synthetic_common'
        node_packages = [report.NODE + '/' + label for label in node_labels]
        common_package = report.COMMON + '/' + common_label
        roster = {'schema': 'standard-token-provisional-roster-v1',
                  'node': node_packages, 'common': [common_package]}
        first_file = node_packages[0] + '/example.go'
        common_file = common_package + '/example.go'
        first_key = (first_file, (1, 1), (1, 4))
        common_key = (common_file, (1, 1), (1, 4))

        def digest(raw):
            return hashlib.sha256(raw).hexdigest()

        def git_blob(raw):
            return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            root, external, cli, output = (temp / name for name in
                                           ('node', 'common', 'cli', 'output'))
            for directory in (root, external, cli):
                directory.mkdir()
            lock_bytes = {'go.mod': b'synthetic module label\n',
                          'go.sum': b'synthetic lock label\n'}
            tracked = {}
            for name, raw in lock_bytes.items():
                (root / name).write_bytes(raw)
                tracked[name] = git_blob(raw)
            entries, file_bytes, widths = {}, {}, {}
            for prefix, base, labels, width in (
                    (report.NODE, root, node_labels, 2),
                    (report.COMMON, external, [common_label], 3)):
                for label in labels:
                    pkg = prefix + '/' + label
                    directory = base / label
                    directory.mkdir()
                    raw = ('synthetic text for ' + label + '\n').encode()
                    (directory / 'example.go').write_bytes(raw)
                    entries[pkg] = {'ImportPath': pkg, 'Module': {'Path': prefix},
                                    'Dir': str(directory), 'GoFiles': ['example.go'],
                                    'Name': label}
                    file_bytes[pkg] = raw
                    widths[pkg] = width
                    if base == root:
                        tracked[label + '/example.go'] = git_blob(raw)

            (cli / 'roster.json').write_text(json.dumps(roster))
            direct = root / '.github/coverage/ordinary'
            for name in ('node-direct-r25.json', 'common-direct/census.json',
                         'node-direct-race/selectors-r28.json'):
                path = direct / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"functions":[]}')
            receipts = [temp / name for name in ('normal', 'race-in', 'race-report', 'common-in')]
            for path in receipts:
                path.mkdir()
            compiler_work = {}
            listed, compiled, formatted = [], [], []

            def fake_subprocess(args, **kwargs):
                # Every permitted call is handled here. No Git, Go or other executable runs.
                self.assertEqual(root, kwargs['cwd'])
                self.assertTrue(kwargs['check'])
                if args == ('git', 'rev-parse', 'HEAD'):
                    return SimpleNamespace(stdout=(subject + '\n').encode())
                if args == ('go', 'version'):
                    return SimpleNamespace(stdout=b'go version go1.26.2 linux/amd64\n')
                if args == ('git', 'ls-tree', '-rz', 'HEAD'):
                    raw = ''.join(f'100644 blob {value}\t{name}\0'
                                  for name, value in sorted(tracked.items())).encode()
                    return SimpleNamespace(stdout=raw)
                if args[:3] == ('go', 'list', '-json'):
                    tail = args[3:]
                    mode = 'race' if tail[0] == '-race' else 'normal'
                    pkg = tail[-1]
                    self.assertEqual(('-race', pkg) if mode == 'race' else (pkg,), tail)
                    listed.append((mode, pkg))
                    return SimpleNamespace(stdout=json.dumps(entries[pkg]).encode())
                if args[:3] == ('go', 'tool', 'cover'):
                    self.assertEqual(('-pkgcfg',), args[3:4])
                    cfg_path = Path(args[4])
                    cfg = json.loads(cfg_path.read_text())
                    pkg = cfg['PkgPath']
                    mode = cfg_path.parent.name.split('-')[0]
                    self.assertEqual('perblock', cfg['Granularity'])
                    self.assertEqual(entries[pkg]['Module']['Path'], cfg['ModulePath'])
                    self.assertEqual(entries[pkg]['Name'], cfg['PkgName'])
                    self.assertEqual(Path(entries[pkg]['Dir']) / 'example.go', Path(args[-1]))
                    self.assertEqual(('-mode=atomic', '-var=goCover_roster_', '-outfilelist'),
                                     args[5:8])
                    self.assertEqual([str(cfg_path.parent / '0.go'), str(cfg_path.parent / '1.go')],
                                     Path(args[8]).read_text().splitlines())
                    meta = Path(cfg['EmitMetaFile'])
                    self.assertEqual(cfg_path.parent / 'meta', meta.parent)
                    meta.write_bytes(b'synthetic compiler marker')
                    compiler_work[meta.parent] = (mode, pkg)
                    compiled.append((mode, pkg))
                    return SimpleNamespace(stdout=b'')
                if args[:4] == ('go', 'tool', 'covdata', 'textfmt'):
                    self.assertEqual(6, len(args))
                    self.assertTrue(args[4].startswith('-i='))
                    self.assertTrue(args[5].startswith('-o='))
                    meta = Path(args[4][3:])
                    mode, pkg = compiler_work[meta]
                    self.assertEqual(meta.parent / 'census.cover', Path(args[5][3:]))
                    raw = f'mode: atomic\n{pkg}/example.go:1.1,1.4 {widths[pkg]} 0\n'
                    Path(args[5][3:]).write_text(raw)
                    formatted.append((mode, pkg))
                    return SimpleNamespace(stdout=b'')
                self.fail(f'unexpected synthetic tool arguments: {args[:3]}')

            def common_profile(directory, mode, checkout, *_args):
                self.assertEqual(receipts[3], directory)
                self.assertEqual(root, checkout)
                return {common_key: (3, mode == 'race')}, digest(mode.encode())

            def reviewed(checkout, manifest, manifest_digest, supplied_roster):
                self.assertEqual(root, checkout)
                self.assertEqual(roster, supplied_roster)
                self.assertEqual(digest((output / 'compiler-manifest.json').read_bytes()),
                                 manifest_digest)
                self.assertEqual(json.loads((output / 'compiler-manifest.json').read_bytes()),
                                 manifest)
                # Attribution is a mocked downstream reporting boundary, not a new admission.
                return {'schema': 'synthetic-reviewed', 'compiler_manifest_sha256': manifest_digest,
                        'full_ordinary_only_denominator': None, 'status': 'NOT_EVALUATED'}

            argv = ['producer.py', '--checkout', str(root), '--subject', subject,
                    '--output', str(output), '--normal-dir', str(receipts[0]),
                    '--race-input', str(receipts[1]), '--race-report', str(receipts[2]),
                    '--common-dir', str(receipts[3])]
            with patch.object(sys, 'argv', argv), patch.object(producer, 'HERE', cli), \
                 patch.object(producer.subprocess, 'run', side_effect=fake_subprocess), \
                 patch.object(producer, 'common_root', return_value=external) as module, \
                 patch.object(report, 'verify_node_source') as verify, \
                 patch.object(report, 'normal_node',
                              return_value=({first_key: (2, True)}, digest(b'normal'))) as normal, \
                 patch.object(report, 'race_node',
                              return_value=({first_key: (2, False)}, digest(b'race'))) as race, \
                 patch.object(report, 'common_mode', side_effect=common_profile) as common, \
                 patch.object(producer.attribution, 'build', side_effect=reviewed) as reviewer:
                producer.main()

            self.assertEqual(1, module.call_count)
            self.assertEqual(2, verify.call_count)
            self.assertEqual([(root, []), (root, [])], [c.args for c in verify.call_args_list])
            self.assertEqual(1, normal.call_count)
            self.assertEqual(1, race.call_count)
            self.assertEqual(2, common.call_count)
            self.assertEqual((receipts[0], [], node_packages), normal.call_args.args)
            self.assertEqual((receipts[1], receipts[2], subject, b'{"functions":[]}',
                              b'{"functions":[]}', [], node_packages), race.call_args.args)
            self.assertEqual(1, reviewer.call_count)
            wanted = [(mode, pkg) for mode in ('normal', 'race')
                      for pkg in node_packages + [common_package]]
            self.assertEqual(wanted, listed)
            self.assertEqual(wanted, compiled)
            self.assertEqual(wanted, formatted)
            self.assertEqual({'compiler-manifest.json', 'compiler-report.json',
                              'reviewed-attribution.json'}, {p.name for p in output.iterdir()})

            manifest_raw = (output / 'compiler-manifest.json').read_bytes()
            manifest = json.loads(manifest_raw)
            metrics = json.loads((output / 'compiler-report.json').read_bytes())
            review = json.loads((output / 'reviewed-attribution.json').read_bytes())
            self.assertEqual(subject, manifest['subject'])
            self.assertEqual(subject, metrics['subject'])
            self.assertTrue(manifest['common_module_verified'])
            self.assertIsNone(manifest['common_module_reason'])
            self.assertEqual(digest(lock_bytes['go.mod']), manifest['go_mod_sha256'])
            self.assertEqual(digest(lock_bytes['go.sum']), manifest['go_sum_sha256'])
            self.assertEqual({'normal': [], 'race': ['race']}, manifest['build_tags'])
            self.assertEqual(digest(manifest_raw), metrics['compiler_manifest_sha256'])
            self.assertEqual(digest(manifest_raw), review['compiler_manifest_sha256'])
            self.assertIsNone(metrics['full_standard_token'])
            self.assertIsNone(review['full_ordinary_only_denominator'])
            self.assertEqual('NOT_EVALUATED', metrics['status'])
            self.assertEqual('NOT_EVALUATED', review['status'])
            for mode, hit in (('normal', 2), ('race', 3)):
                with self.subTest(mode=mode):
                    self.assertEqual(set(entries), set(manifest['mode'][mode]))
                    for module_name in ('node', 'common'):
                        self.assertEqual({'status': 'bound_partial_diagnostic',
                                          'profile_sha256': digest(mode.encode())},
                                         metrics['inputs'][mode + '_' + module_name])
                    for pkg, row in manifest['mode'][mode].items():
                        file = pkg + '/example.go'
                        self.assertEqual('metadata_present', row['status'])
                        self.assertEqual({file: digest(file_bytes[pkg])}, row['sources'])
                        self.assertEqual([[file, 1, 1, 1, 4, widths[pkg]]], row['blocks'])
                        raw = f'mode: atomic\n{file}:1.1,1.4 {widths[pkg]} 0\n'.encode()
                        self.assertEqual(digest(raw), row['compiler_profile_sha256'])
                    stat = metrics['aggregate'][mode]['roster']
                    self.assertEqual((39, 39, 2, 0), (
                        stat['packages_requested'], stat['packages_with_census'],
                        stat['packages_complete'], stat['packages_census_unavailable']))
                    self.assertEqual(39, stat['known_compiler_blocks'])
                    self.assertEqual(37, stat['known_missing_blocks'])
                    self.assertEqual(79, stat['known_expected_statements'])
                    self.assertEqual({'covered': hit, 'total': 5}, stat['observed_statements'])
                    self.assertIsNone(stat['complete_statements'])
                    self.assertEqual({'not_observed': 37, 'partial': 0, 'complete': 2,
                                      'invalid': 0, 'census_unavailable': 0},
                                     stat['packages_observation_status'])
                    absent = metrics['mode'][mode][node_packages[1]]
                    self.assertEqual('not_observed', absent['observation_status'])
                    self.assertIsNone(absent['observed_statements'])
                    self.assertEqual({'covered': 2 if mode == 'normal' else 0, 'total': 2},
                                     metrics['mode'][mode][node_packages[0]]['observed_statements'])
                    self.assertEqual({'covered': 3 if mode == 'race' else 0, 'total': 3},
                                     metrics['mode'][mode][common_package]['observed_statements'])
