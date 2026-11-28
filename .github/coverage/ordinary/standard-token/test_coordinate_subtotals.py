"""Synthetic coordinate/statement report fixtures, independent of attribution proposals."""
import unittest

import producer
import report
import test_report as report_fixtures


class CoordinateSubtotalTests(unittest.TestCase):
    def test_separate_mode_and_module_subtotals_with_zero_only_package(self):
        alpha = report.NODE + '/alpha'
        beta = report.NODE + '/beta'
        gamma = report.COMMON + '/gamma'

        def coordinate(pkg, line, empty=False):
            return pkg + '/sample.go', (line, 1), (line, 1 if empty else 4)

        a2, a3, az = coordinate(alpha, 1), coordinate(alpha, 2), coordinate(alpha, 3, True)
        bz = coordinate(beta, 1, True)
        g4, gz = coordinate(gamma, 1), coordinate(gamma, 2, True)
        expected = {alpha: {a2: 2, a3: 3, az: 0}, beta: {bz: 0}, gamma: {g4: 4, gz: 0}}
        # Distinct valid profile observations per mode. A zero-width coordinate
        # may be present or missing without contributing any statement weight.
        profiles = {
            'normal': {a2: (2, True), az: (0, False), bz: (0, True), g4: (4, False), gz: (0, True)},
            'race': {a2: (2, False), a3: (3, True), az: (0, True), gz: (0, True)},
        }
        fields = ('compiler_blocks', 'observed_blocks', 'missing_blocks', 'expected_statements',
                  'observed_statements', 'missing_statements', 'complete_subset_statements',
                  'observation_status', 'status')
        package_oracle = {
            'normal': {
                alpha: (3, 2, 1, 5, {'covered': 2, 'total': 2}, 3, None, 'partial', 'incomplete'),
                beta: (1, 1, 0, None, None, None, None, 'complete', 'incomplete'),
                gamma: (2, 2, 0, 4, {'covered': 0, 'total': 4}, 0, {'covered': 0, 'total': 4}, 'complete', 'complete'),
            },
            'race': {
                alpha: (3, 3, 0, 5, {'covered': 3, 'total': 5}, 0, {'covered': 3, 'total': 5}, 'complete', 'complete'),
                beta: (1, None, 1, None, None, None, None, 'not_observed', 'incomplete'),
                gamma: (2, 1, 1, 4, None, 4, None, 'partial', 'incomplete'),
            },
        }
        aggregate_fields = ('packages_requested', 'packages_with_census', 'packages_complete',
                            'packages_census_unavailable', 'known_compiler_blocks', 'known_missing_blocks',
                            'known_expected_statements', 'observed_statements', 'complete_statements')
        aggregate_oracle = {
            'normal': {
                'node': (2, 2, 0, 0, 4, 1, 5, {'covered': 2, 'total': 2}, None),
                'common': (1, 1, 1, 0, 2, 0, 4, {'covered': 0, 'total': 4}, {'covered': 0, 'total': 4}),
                'roster': (3, 3, 1, 0, 6, 1, 9, {'covered': 2, 'total': 6}, None),
            },
            'race': {
                'node': (2, 2, 1, 0, 4, 1, 5, {'covered': 3, 'total': 5}, None),
                'common': (1, 1, 0, 0, 2, 1, 4, None, None),
                'roster': (3, 3, 1, 0, 6, 2, 9, {'covered': 3, 'total': 5}, None),
            },
        }
        status_oracle = {
            'normal': {'not_observed': 0, 'partial': 1, 'complete': 2, 'invalid': 0, 'census_unavailable': 0},
            'race': {'not_observed': 1, 'partial': 1, 'complete': 1, 'invalid': 0, 'census_unavailable': 0},
        }
        for mode, profile in profiles.items():
            with self.subTest(mode=mode):
                rows = {pkg: producer.package_measure(blocks, profile, pkg) for pkg, blocks in expected.items()}
                for pkg, row in rows.items():
                    self.assertEqual(package_oracle[mode][pkg], tuple(row[k] for k in fields))
                subtotals = {'node': producer.aggregate([rows[alpha], rows[beta]]),
                             'common': producer.aggregate([rows[gamma]]),
                             'roster': producer.aggregate(list(rows.values()))}
                for key, subtotal in subtotals.items():
                    self.assertEqual(aggregate_oracle[mode][key], tuple(subtotal[k] for k in aggregate_fields))
                self.assertEqual(status_oracle[mode], subtotals['roster']['packages_observation_status'])
                self.assertEqual(subtotals['roster'], producer.aggregate(list(reversed(list(rows.values())))))

    def test_profile_union_with_zero_width_and_independent_positive_weights(self):
        pkg = report.NODE + '/sample'
        file = pkg + '/math.go'
        first = report.parse_profile(f'mode: atomic\n{file}:1.1,1.4 2 0\n{file}:3.1,3.1 0 4\n'.encode())
        second = report.parse_profile(f'mode: atomic\n{file}:1.1,1.4 2 9\n{file}:2.1,2.4 5 0\n{file}:3.1,3.1 0 0\n'.encode())
        expected = producer.independent_blocks(
            f'mode: atomic\n{file}:1.1,1.4 2 0\n{file}:2.1,2.4 5 0\n{file}:3.1,3.1 0 0\n'.encode(), {file: 'fixture'})
        total = {'expected_statements': 7, 'observed_statements': {'covered': 2, 'total': 7},
                 'missing_statements': 0, 'complete_subset_statements': {'covered': 2, 'total': 7}}
        self.assertEqual(total, report.tally(expected, [first, second]))
        self.assertEqual(total, report.tally(expected, [second, first, second]))
        self.assertEqual({'covered': 0, 'total': 2}, report.counts(first, pkg))
        zero_only = {k: v for k, v in first.items() if v[0] == 0}
        self.assertEqual({'covered': 0, 'total': 0}, report.counts(zero_only, pkg))
        self.assertIsNone(report.counts({}, pkg))
        self.assertIsNone(report.tally(expected, [zero_only])['observed_statements'])

    def test_report_keeps_unreviewed_zero_coordinate_out_of_reviewed_subtotals(self):
        # Reuse only the existing synthetic artifact constructor, not its tests.
        fixture = report_fixtures.BoundFixtureTests('test_full_subset_is_not_gate')
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.normal()
        fixture.race()
        fixture.common()
        unreviewed = fixture.roster['node'][1]
        path = fixture.node_dir / 'coverage-input.cover'
        raw = path.read_bytes() + f'{unreviewed}/sample.go:7.1,7.1 0 3\n'.encode()
        path.write_bytes(raw)
        report_fixtures.store(fixture.node_dir / 'input.json', {
            'status': 'bound', 'profile_before': 'absent', 'primary_outcome': 'success',
            'profile_sha256': report.sha(raw)})
        fixture.artifacts(fixture.node_dir, raw, fixture.nf,
                          'node-direct-r25.json', 'node-direct-r25-bound-manifest.json')
        value = fixture.build()
        rows = {row['package']: row for row in value['packages']}
        unknown = rows[unreviewed]
        self.assertEqual('unreviewed', unknown['attribution'])
        self.assertEqual({'covered': 0, 'total': 0}, unknown['node_primary_mixed_normal'])
        null = {k: None for k in ('expected_statements', 'observed_statements', 'missing_statements',
                                   'complete_subset_statements')}
        self.assertEqual(null, unknown['normal'])
        self.assertEqual(null, unknown['race'])
        self.assertEqual({'covered': 3, 'total': 5}, value['attributed_subset']['normal']['complete_subset_statements'])
        self.assertEqual({'covered': 2, 'total': 5}, value['attributed_subset']['race']['complete_subset_statements'])
        self.assertEqual('NOT_EVALUATED', value['status'])
        self.assertEqual({'expected_statements': None, 'covered_statements': None, 'percent': None},
                         value['full_standard_token'])
