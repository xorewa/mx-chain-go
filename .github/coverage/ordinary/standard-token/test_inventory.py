"""Synthetic statement/coordinate inventory regressions; no product execution."""
import unittest

import attribution
import producer
from test_attribution import NODE, EXTRA, COMMON, compiler, joined
from test_producer import PKG, FILE, K1, K2


class InventoryTests(unittest.TestCase):
    def test_zero_width_census_is_available_without_statement_denominator(self):
        zero = (FILE, (4, 1), (4, 1))
        absent = producer.package_measure({zero: 0}, {}, PKG)
        present = producer.package_measure({zero: 0}, {zero: (0, False)}, PKG)
        unknown = producer.package_measure(None, {}, PKG)
        self.assertEqual('not_observed', absent['observation_status'])
        self.assertEqual((1, None, 1), tuple(absent[key] for key in
                         ('compiler_blocks', 'observed_blocks', 'missing_blocks')))
        self.assertEqual('complete', present['observation_status'])
        self.assertEqual((1, 1, 0), tuple(present[key] for key in
                         ('compiler_blocks', 'observed_blocks', 'missing_blocks')))
        for row in (absent, present, unknown):
            self.assertIsNone(row['complete_subset_statements'])
            self.assertIsNone(row['observed_statements'])
        result = producer.aggregate([absent, present, unknown])
        self.assertEqual(2, result['packages_with_census'])
        self.assertEqual(0, result['known_expected_statements'])
        self.assertEqual(1, result['packages_census_unavailable'])
        self.assertEqual(2, result['known_compiler_blocks'])
        self.assertEqual(1, result['known_missing_blocks'])
        self.assertIsNone(result['complete_statements'])
        self.assertIsNone(producer.aggregate([unknown])['known_compiler_blocks'])

    def test_partial_coordinate_inventory_is_not_missing_statement_coverage(self):
        zero = (FILE, (4, 1), (4, 1))
        expected = {K1: 2, K2: 3, zero: 0}
        partial = producer.package_measure(expected, {K1: (2, False), K2: (3, True)}, PKG)
        self.assertEqual('partial', partial['observation_status'])
        self.assertEqual('complete', partial['status'])
        self.assertEqual({'covered': 3, 'total': 5}, partial['complete_subset_statements'])
        self.assertEqual((3, 2, 1), tuple(partial[k] for k in
                         ('compiler_blocks', 'observed_blocks', 'missing_blocks')))
        invalid = producer.package_measure(expected, {K1: (3, True)}, PKG)
        self.assertEqual('invalid', invalid['observation_status'])
        self.assertIsNone(invalid['observed_blocks'])
        self.assertEqual(3, invalid['missing_blocks'])
        summary = producer.aggregate([partial, invalid])
        self.assertEqual({'not_observed': 0, 'partial': 1, 'complete': 0, 'invalid': 1,
                          'census_unavailable': 0}, summary['packages_observation_status'])
        self.assertEqual(4, summary['known_missing_blocks'])
        self.assertIsNone(summary['complete_statements'])

    def test_unclassified_positive_blocks_exclude_zero_width_metadata(self):
        value = joined()
        self.assertIsNone(value['full_ordinary_only_denominator'])
        for mode in attribution.MODES:
            data = value['modes'][mode]
            rows = {row['package']: row for row in data['packages']}
            self.assertEqual((3, 1, 1), tuple(rows[NODE][key] for key in
                             ('compiler_blocks_mixed', 'compiler_zero_statement_blocks',
                              'unresolved_mixed_positive_blocks')))
            self.assertEqual(2, rows[EXTRA]['unresolved_mixed_positive_blocks'])
            self.assertEqual(1, rows[COMMON]['unresolved_mixed_positive_blocks'])
            self.assertEqual((9, 3, 15, 4, 11), tuple(data[key] for key in
                             ('known_compiler_blocks_mixed', 'known_compiler_zero_statement_blocks',
                              'known_compiler_statements_mixed', 'known_unresolved_mixed_positive_blocks',
                              'known_unresolved_mixed_statements')))

    def test_unknown_census_is_not_zero_or_classified(self):
        c = compiler()
        c['mode']['normal'][EXTRA] = {'status': 'unavailable'}
        for pkg in (NODE, EXTRA, COMMON):
            c['mode']['race'][pkg] = {'status': 'unavailable'}
        value = joined(c)
        normal = value['modes']['normal']
        race = value['modes']['race']
        self.assertEqual((2, 1, 6, 2), tuple(normal[key] for key in
                         ('packages_with_compiler_census', 'packages_without_compiler_census',
                          'known_compiler_blocks_mixed', 'known_unresolved_mixed_positive_blocks')))
        for key in ('compiler_blocks_mixed', 'compiler_zero_statement_blocks',
                    'unresolved_mixed_positive_blocks', 'unresolved_mixed_statements'):
            self.assertIsNone(normal['packages'][1][key])
        self.assertEqual(3, race['packages_without_compiler_census'])
        for key in ('known_compiler_blocks_mixed', 'known_compiler_zero_statement_blocks',
                    'known_compiler_statements_mixed', 'known_unresolved_mixed_positive_blocks',
                    'known_unresolved_mixed_statements'):
            self.assertIsNone(race[key])
        self.assertIsNone(value['full_ordinary_only_denominator'])


if __name__ == '__main__':
    unittest.main()
