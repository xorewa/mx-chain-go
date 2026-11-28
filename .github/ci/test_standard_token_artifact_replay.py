"""Replay synthetic portable artifact layouts through the actual diagnostic readers."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import test_standard_token_input_uploads as wiring

DIAGNOSTIC = Path(__file__).resolve().parents[1] / 'coverage/ordinary/standard-token'
with patch.object(sys, 'path', [str(DIAGNOSTIC), *sys.path]):
    import producer
    import report

SUBJECT = 'a' * 40
NODE = report.NODE + '/synthetic'
KEY = (NODE + '/label.go', (1, 1), (2, 1))
REVIEW = '8bd94f4dd795da74a2522c6d5b006bca1310fa352c9d1b1c818b678f449b7554'
NORMAL_READER = 'Upload diagnostic standard-token roster reports'
RACE_READER = 'Upload read-only Node direct race diagnostic'
PRIMARY = 'Upload coverage profile, raw tests and hybrid report'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def store(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def report_files(raw, functions, covered):
    manifest = encode({'profile_sha256': sha(raw), 'functions': functions})
    observed = {'covered': covered, 'total': 2}
    result = encode({'profile_status': 'present', 'profile_mode': 'atomic',
                     'profile_sha256': sha(raw), 'manifest_sha256': sha(manifest),
                     'expected_statements': 2, 'observed_statements': observed,
                     'aggregate_statements': observed})
    return manifest, result


class StandardTokenArtifactReplayTests(unittest.TestCase):
    def transfer(self, root, step, files, destination):
        name = next(line.strip().removeprefix('name: ') for line in wiring.step(step).splitlines()
                    if line.strip().startswith('name: ')).replace('${{ github.sha }}', SUBJECT)
        self.assertTrue(name.endswith(SUBJECT))
        allowlist = {path.rsplit('/', 1)[-1] for path in wiring.paths(step)}
        self.assertTrue(set(files) <= allowlist)
        archive = root / (name + '.zip')
        self.assertFalse(archive.exists(), 'artifact names must be distinct')
        with zipfile.ZipFile(archive, 'w') as zipped:
            for member, raw in sorted(files.items()):
                zipped.writestr(member, raw)
        destination.mkdir(exist_ok=True)
        with zipfile.ZipFile(archive) as zipped:
            self.assertCountEqual(files, zipped.namelist())
            for member in files:
                raw = zipped.read(member)
                target = destination / member
                if target.exists():
                    # The normal receipt is present in both portable layouts.
                    self.assertEqual(target.read_bytes(), raw)
                else:
                    target.write_bytes(raw)

    def test_reassembled_readers_preserve_observed_zero_and_absence(self):
        for has_normal in (True, False):
            with self.subTest(has_normal=has_normal), tempfile.TemporaryDirectory() as tmp:
                self.replay(Path(tmp), has_normal)

    def replay(self, root, has_normal):
        source = root / 'source'
        label = b'synthetic display label\n'
        store(source / 'synthetic/label.go', label)
        functions = [{'source': 'synthetic/label.go', 'source_sha256': sha(label),
                      'profile_file': KEY[0], 'name': 'Label', 'span': [1, 1, 3, 1],
                      'blocks': [{'start': [1, 1], 'end': [2, 1], 'statements': 2}]}]
        node_template = encode({'functions': functions})
        selectors = encode({'synthetic_selector': True})
        ordinary = source / '.github/coverage/ordinary'
        store(ordinary / 'node-direct-r25.json', node_template)
        store(ordinary / 'common-direct/census.json', encode({'functions': []}))
        store(ordinary / 'node-direct-race/selectors-r28.json', selectors)
        roster = {'schema': 'standard-token-provisional-roster-v1', 'node': [NODE], 'common': []}
        cli = root / 'cli'
        store(cli / 'roster.json', encode(roster))

        race_raw = f'mode: atomic\n{KEY[0]}:1.1,2.1 2 1\n'.encode()
        normal_raw = f'mode: atomic\n{KEY[0]}:1.1,2.1 2 0\n'.encode()
        race_receipt = {'run_mode': 'race', 'subject': SUBJECT, 'selector_review_sha256': REVIEW,
                        'selector_manifest_sha256': sha(selectors), 'census_sha256': sha(node_template),
                        'profile_sha256': sha(race_raw), 'test_exit': 0}
        race_manifest, race_report = report_files(race_raw, functions, 2)
        race_input_dir, race_report_dir = root / 'race-input', root / 'race-report'
        self.transfer(root, wiring.RACE, {'coverage.out': race_raw,
                                         'provenance.json': encode(race_receipt)}, race_input_dir)
        self.transfer(root, RACE_READER, {'scope.txt': b'synthetic scope\n',
                                         'provenance.json': encode(dict(race_receipt, status='caller_receipt_matched')),
                                         'bound-manifest.json': race_manifest,
                                         'report.json': race_report}, race_report_dir)
        producer_receipt = (race_input_dir / 'provenance.json').read_bytes()
        reader_receipt = (race_report_dir / 'provenance.json').read_bytes()
        self.assertNotEqual(producer_receipt, reader_receipt)
        self.assertEqual(dict(json.loads(producer_receipt), status='caller_receipt_matched'),
                         json.loads(reader_receipt))
        self.assertEqual(sha((race_input_dir / 'coverage.out').read_bytes()), race_receipt['profile_sha256'])

        normal_receipt = {'profile_before': 'absent', 'primary_outcome': 'success',
                          'status': 'bound' if has_normal else 'unavailable',
                          'reason': None if has_normal else 'current_profile_absent',
                          'profile_sha256': sha(normal_raw) if has_normal else None}
        normal_input = {'input.json': encode(normal_receipt)}
        normal_reader = {'input.json': encode(normal_receipt), 'scope.txt': b'synthetic scope\n',
                         'node.json': b'{}\n', 'common.json': b'{}\n',
                         'node-direct-scope.txt': b'synthetic scope\n'}
        if has_normal:
            manifest, result = report_files(normal_raw, functions, 0)
            normal_reader.update({'node-direct-r25.json': result, 'node-direct-r25-bound-manifest.json': manifest})
        else:
            normal_reader['node-direct-r25.json'] = encode({'status': 'unavailable', 'aggregate_statements': None})
        normal_dir = root / 'normal'
        self.transfer(root, NORMAL_READER, normal_reader, normal_dir)
        self.transfer(root, wiring.NORMAL, normal_input, normal_dir)
        self.assertEqual({'input.json'}, set(normal_input))
        self.assertFalse((normal_dir / 'coverage-input.cover').exists())
        # Existing primary coverage artifact is separate and may have a profile
        # even when the current snapshot receipt is unavailable. Never infer
        # availability from the mere existence of that artifact.
        primary_dir = root / 'primary'
        self.transfer(root, PRIMARY, {'coverage.out': normal_raw}, primary_dir)
        receipt = json.loads((normal_dir / 'input.json').read_bytes())
        if receipt['status'] == 'bound':
            raw = (primary_dir / 'coverage.out').read_bytes()
            self.assertEqual(receipt['profile_sha256'], sha(raw))
            store(normal_dir / 'coverage-input.cover', raw)
        else:
            self.assertIsNone(receipt['profile_sha256'])
        self.assertEqual(has_normal, (normal_dir / 'coverage-input.cover').is_file())

        output = root / 'report.json'
        argv = ['report.py', '--checkout', str(source), '--subject', SUBJECT,
                '--normal-dir', str(normal_dir), '--race-input', str(race_input_dir),
                '--race-report', str(race_report_dir), '--output', str(output)]
        with patch.object(sys, 'argv', argv), patch.object(report, 'HERE', cli), \
             patch.object(report.subprocess, 'run', side_effect=AssertionError('unexpected executable')), \
             patch.object(report.subprocess, 'check_output', return_value=SUBJECT + '\n') as git:
            report.main()
        git.assert_called_once_with(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True)
        result = json.loads(output.read_bytes())
        self.assertEqual(SUBJECT, result['subject'])
        self.assertEqual('NOT_EVALUATED', result['status'])
        self.assertEqual({'expected_statements': None, 'covered_statements': None, 'percent': None},
                         result['full_standard_token'])
        self.assertEqual(sha(node_template), result['node_census_sha256'])
        expected_race = {'covered': 2, 'total': 2}
        expected_normal = {'covered': 0, 'total': 2} if has_normal else None
        for mode, expected in (('normal', expected_normal), ('race', expected_race)):
            stats = result['attributed_subset'][mode]
            self.assertEqual(2, stats['expected_statements'])
            self.assertEqual(expected, stats['observed_statements'])
            self.assertEqual(expected, stats['complete_subset_statements'])
            self.assertEqual(2 if expected is None else 0, stats['missing_statements'])

        with patch.object(producer.subprocess, 'run', side_effect=AssertionError('unexpected executable')), \
             patch.object(producer.subprocess, 'check_output', side_effect=AssertionError('unexpected executable')):
            profiles, receipts = producer.inputs(source, SUBJECT, roster, normal_dir,
                                                 race_input_dir, race_report_dir, None)
            self.assertEqual(result['inputs'], receipts)
            self.assertEqual({KEY: (2, True)}, profiles['race', 'node'])
            self.assertEqual({KEY: (2, False)} if has_normal else {}, profiles['normal', 'node'])
            self.assertEqual('bound_partial_diagnostic', receipts['race_node']['status'])
            self.assertEqual(race_receipt['profile_sha256'], receipts['race_node']['profile_sha256'])
            self.assertEqual('bound_partial_diagnostic' if has_normal else 'unavailable_or_invalid',
                             receipts['normal_node']['status'])
            self.assertEqual(normal_receipt['profile_sha256'], receipts['normal_node']['profile_sha256'])
            for mode, expected in (('normal', expected_normal), ('race', expected_race)):
                measured = producer.package_measure({KEY: 2}, profiles[mode, 'node'], NODE)
                self.assertEqual(expected, measured['observed_statements'])
                self.assertEqual(expected, measured['complete_subset_statements'])
                self.assertEqual('not_observed' if expected is None else 'complete',
                                 measured['observation_status'])
