"""Pure synthetic producer arithmetic and source identity checks."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import producer
import report

PKG = report.NODE + '/fixture'
FILE = PKG + '/demo.go'
K1 = (FILE, (1, 1), (1, 4))
K2 = (FILE, (2, 1), (2, 4))


class ProducerTests(unittest.TestCase):
    def test_compiler_metadata_is_independent_not_coverage(self):
        raw = f'mode: atomic\n{FILE}:1.1,1.4 2 0\n{FILE}:2.1,2.4 3 0\n'.encode()
        expected = producer.independent_blocks(raw, {FILE: 'x'})
        self.assertEqual({K1: 2, K2: 3}, expected)
        value = producer.package_measure(expected, {}, PKG)
        self.assertEqual('incomplete', value['status'])
        self.assertIsNone(value['observed_statements'])
        self.assertEqual(5, value['missing_statements'])
        with self.assertRaises(ValueError):
            producer.independent_blocks(raw.replace(b'3 0', b'3 1'), {FILE: 'x'})
        with self.assertRaises(ValueError):
            producer.independent_blocks(raw, {})

    def test_zero_is_observed_and_missing_is_distinct(self):
        expected = {K1: 2, K2: 3}
        partial = producer.package_measure(expected, {K1: (2, False)}, PKG)
        self.assertEqual({'covered': 0, 'total': 2}, partial['observed_statements'])
        self.assertEqual(3, partial['missing_statements'])
        self.assertIsNone(partial['complete_subset_statements'])
        complete = producer.package_measure(expected, {K1: (2, False), K2: (3, True)}, PKG)
        self.assertEqual('complete', complete['status'])
        self.assertEqual({'covered': 3, 'total': 5}, complete['complete_subset_statements'])
        zero = producer.package_measure(expected, {K1: (2, False), K2: (3, False)}, PKG)
        self.assertEqual({'covered': 0, 'total': 5}, zero['complete_subset_statements'])

    def test_mismatches_reject_whole_package_and_other_packages_do_not_count(self):
        expected = {K1: 2}
        for bad in ({K1: (1, True)}, {K2: (3, True), K1: (2, True)}):
            value = producer.package_measure(expected, bad, PKG)
            self.assertEqual('profile_census_mismatch', value['status'])
            self.assertIsNone(value['observed_statements'])
        unrelated = (report.NODE + '/other/demo.go', K1[1], K1[2])
        value = producer.package_measure(expected, {K1: (2, True), unrelated: (3, True)}, PKG)
        self.assertEqual({'covered': 2, 'total': 2}, value['complete_subset_statements'])
        self.assertEqual('census_unavailable', producer.package_measure(None, {}, PKG)['status'])

    def test_aggregate_completeness(self):
        expected = {K1: 2}
        measured = producer.package_measure(expected, {K1: (2, True)}, PKG)
        absent = producer.package_measure(expected, {}, PKG)
        unbound = producer.package_measure(None, {}, PKG)
        x = producer.aggregate([measured, absent, unbound])
        self.assertEqual((3, 2, 1), (x['packages_requested'], x['packages_with_census'], x['packages_complete']))
        self.assertEqual(4, x['known_expected_statements'])
        self.assertEqual({'covered': 2, 'total': 2}, x['observed_statements'])
        self.assertIsNone(x['complete_statements'])
        self.assertEqual({'covered': 2, 'total': 2}, producer.aggregate([measured])['complete_statements'])
        self.assertIsNone(producer.aggregate([])['known_expected_statements'])

    def test_selected_source_digest_and_git_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            directory = base / 'fixture'
            directory.mkdir()
            raw = b'package fixture\nfunc Foo() {}\n'
            (directory / 'demo.go').write_bytes(raw)
            (directory / 'demo_test.go').write_bytes(b'package fixture\n')
            entry = {'ImportPath': PKG, 'Name': 'fixture', 'Dir': str(directory),
                     'Module': {'Path': report.NODE}, 'GoFiles': ['demo.go']}
            tracked = {'fixture/demo.go': producer.blob(raw)}
            self.assertEqual((directory, {FILE: report.sha(raw)}), producer.sources(entry, PKG, base, tracked))
            for patch in ({'GoFiles': ['demo_test.go']}, {'GoFiles': ['demo.go', 'demo.go']},
                          {'GoFiles': ['../demo.go']}, {'CgoFiles': ['demo.go']}, {'ImportPath': 'wrong'}, {'Dir': str(base)}):
                with self.subTest(patch=patch), self.assertRaises(ValueError):
                    producer.sources(dict(entry, **patch), PKG, base, tracked)
            (directory / 'demo.go').write_bytes(raw + b'\n')
            with self.assertRaises(ValueError):
                producer.sources(entry, PKG, base, tracked)

    def test_stale_direct_census_does_not_block_independent_inputs(self):
        root = Path(__file__).resolve().parents[4]
        roster = json.loads((Path(__file__).parent / 'roster.json').read_bytes())
        with patch.object(report, 'verify_node_source', side_effect=ValueError('stale')), \
             patch.object(report, 'common_mode', return_value=({K1: (2, True)}, 'bound')):
            profiles, receipts = producer.inputs(root, 'subject', roster, root, root, root, root)
        for mode in producer.MODES:
            self.assertEqual({}, profiles[mode, 'node'])
            self.assertEqual('unavailable_or_invalid', receipts[mode + '_node']['status'])
            self.assertIn(K1, profiles[mode, 'common'])
            self.assertEqual('bound_partial_diagnostic', receipts[mode + '_common']['status'])

    def test_object_sequence_and_portable_errors(self):
        self.assertEqual([{'a': 1}, {'b': 2}], list(producer.objects(b'{"a":1}\n{"b":2}\n')))
        with self.assertRaises(json.JSONDecodeError):
            list(producer.objects(b'{'))
        self.assertEqual('source_missing', producer.error_reason(ValueError('source_missing')))
        self.assertEqual('source_or_tool_input_unavailable', producer.error_reason(ValueError('/private/file')))


if __name__ == '__main__':
    unittest.main()
