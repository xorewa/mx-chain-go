"""Static and synthetic contract for portable standard-token profile inputs."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / 'workflows/drwa-ci.yml'
RACE = 'Retain current Node direct race producer inputs'
NORMAL = 'Retain current ordinary normal bound input'
RACE_DIR = '${{ steps.node-direct-race-input.outputs.directory }}'
NORMAL_DIR = '${{ steps.ordinary-normal-output.outputs.directory }}'
READER_DIR = '${{ steps.node-direct-race-report.outputs.directory }}'


def step(name):
    return WORKFLOW.read_text().split(f'      - name: {name}\n', 1)[1].split('      - name: ', 1)[0]


def paths(name):
    body = step(name).split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0]
    return [line.strip() for line in body.splitlines() if line.strip()]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def selected_files(name, expression, directory):
    # The upload step uses only literal files relative to the current output.
    result = {}
    for value in paths(name):
        prefix = expression + '/'
        if not value.startswith(prefix):
            raise AssertionError('unexpected artifact input directory')
        file = directory / value.removeprefix(prefix)
        if file.is_file():
            result[file.name] = file.read_bytes()
    return result


class StandardTokenInputUploadsTests(unittest.TestCase):
    def test_literal_distinct_artifact_allowlists_and_current_success_conditions(self):
        race, normal = step(RACE), step(NORMAL)
        producer = step('Produce reviewed Node direct race input (partial diagnostic only)')
        self.assertIn('id: node-direct-race-producer', producer)
        self.assertIn('diagnostic.py --output "$NODE_DIRECT_RACE_INPUT"', producer)
        self.assertIn("if: always() && steps.isolation-preflight.outcome == 'success' && "
                      "steps.node-direct-race-input.outcome == 'success' && "
                      "steps.node-direct-race-producer.outcome == 'success' && "
                      "steps.node-direct-race-input.outputs.directory != ''", race)
        self.assertIn("if: always() && steps.isolation-preflight.outcome == 'success' && "
                      "steps.ordinary-normal-output.outcome == 'success' && "
                      "steps.ordinary-normal-output.outputs.directory != ''", normal)
        for text in (race, normal):
            self.assertIn('continue-on-error: true', text)
            self.assertIn('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02', text)
            self.assertIn('if-no-files-found: warn', text)
        self.assertIn('name: standard-token-node-direct-race-input-${{ github.sha }}', race)
        self.assertIn('name: standard-token-node-normal-input-${{ github.sha }}', normal)
        self.assertEqual([RACE_DIR + '/coverage.out', RACE_DIR + '/provenance.json'], paths(RACE))
        self.assertEqual([NORMAL_DIR + '/input.json'], paths(NORMAL))
        self.assertIn('coverage.out', paths('Upload coverage profile, raw tests and hybrid report'))
        reader = paths('Upload read-only Node direct race diagnostic')
        self.assertIn(READER_DIR + '/provenance.json', reader)
        self.assertNotEqual(RACE_DIR, READER_DIR)
        for value in paths(RACE) + paths(NORMAL):
            self.assertNotIn('*', value)
            self.assertNotIn('/raw/', value)
            self.assertNotIn('.stdout', value)
            self.assertNotIn('.stderr', value)

    def test_current_raw_profiles_match_separate_receipts_and_exclude_other_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            race, normal, reader, previous = (root / name for name in ('race', 'normal', 'reader', 'previous'))
            for d in (race, normal, reader, previous):
                d.mkdir()
            raw = race / 'raw'
            raw.mkdir()
            (raw / 'toy.stdout').write_bytes(b'not a portable file')
            (raw / 'toy.stderr').write_bytes(b'not a portable file')
            (previous / 'coverage.out').write_bytes(b'previous attempt')
            coverage_race = b'mode: atomic\nexample.invalid/sample/label.go:1.1,2.1 1 1\n'
            coverage_normal = b'mode: atomic\nexample.invalid/sample/label.go:1.1,2.1 1 0\n'
            race_receipt = {'run_mode': 'race', 'subject': 'a' * 40, 'test_exit': 0,
                            'selector_review_sha256': 'b' * 64, 'selector_manifest_sha256': 'c' * 64,
                            'census_sha256': 'd' * 64, 'profile_sha256': sha(coverage_race)}
            normal_receipt = {'profile_before': 'absent', 'primary_outcome': 'success',
                              'status': 'bound', 'reason': None, 'profile_sha256': sha(coverage_normal)}
            (race / 'coverage.out').write_bytes(coverage_race)
            (race / 'provenance.json').write_text(json.dumps(race_receipt))
            (reader / 'provenance.json').write_text(json.dumps(dict(race_receipt, status='caller_receipt_matched')))
            (normal / 'input.json').write_text(json.dumps(normal_receipt))
            (normal / 'coverage-input.cover').write_bytes(coverage_normal)
            (normal / 'other.txt').write_bytes(b'not allowlisted')
            r = selected_files(RACE, RACE_DIR, race)
            n = selected_files(NORMAL, NORMAL_DIR, normal)
            self.assertEqual({'coverage.out', 'provenance.json'}, set(r))
            self.assertEqual({'input.json'}, set(n))
            self.assertEqual(race_receipt, json.loads(r['provenance.json']))
            self.assertEqual(dict(json.loads(r['provenance.json']), status='caller_receipt_matched'),
                             json.loads((reader / 'provenance.json').read_bytes()))
            self.assertEqual(sha(r['coverage.out']), race_receipt['profile_sha256'])
            self.assertEqual(sha(coverage_normal), json.loads(n['input.json'])['profile_sha256'])
            self.assertNotEqual(r['coverage.out'], coverage_normal)
            self.assertEqual(b'previous attempt', (previous / 'coverage.out').read_bytes())

            # An unavailable normal input still has only its current receipt,
            # not a substitute profile or an invented zero count.
            (normal / 'coverage-input.cover').unlink()
            unavailable = dict(normal_receipt, status='unavailable', reason='current_profile_absent',
                               profile_sha256=None)
            (normal / 'input.json').write_text(json.dumps(unavailable))
            self.assertEqual({'input.json'}, set(selected_files(NORMAL, NORMAL_DIR, normal)))
            self.assertIsNone(json.loads(selected_files(NORMAL, NORMAL_DIR, normal)['input.json'])['profile_sha256'])
            self.assertEqual({}, selected_files(RACE, RACE_DIR, root / 'not-produced'))
