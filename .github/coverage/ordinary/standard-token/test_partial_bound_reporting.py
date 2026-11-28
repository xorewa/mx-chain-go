"""Synthetic bound partial reports: missing reviewed data is not mixed credit."""
import unittest

import report
import test_report as fixtures


class PartialBoundReportingTests(unittest.TestCase):
    def test_valid_disjoint_normal_and_partial_race_keep_unknown_attribution(self):
        fixture = fixtures.BoundFixtureTests('test_full_subset_is_not_gate')
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()

        # Two independently known Node weights, 2 and 5; Common adds 3.
        fixture.nf[0]['span'] = [1, 1, 6, 1]
        fixture.nf[0]['blocks'].append({
            'start': [4, 1], 'end': [5, 1], 'statements': 5})
        fixture.nt = fixtures.encoded({'functions': fixture.nf})
        unreviewed = fixture.roster['node'][1]

        def bind(directory, raw, report_name, manifest_name, observed):
            # The producer's expected weights are literal, not computed by
            # the tally or profile parser that build_report is testing.
            manifest = {'profile_sha256': report.sha(raw), 'functions': fixture.nf}
            fixtures.store(directory / manifest_name, manifest)
            fixtures.store(directory / report_name, {
                'profile_status': 'present', 'profile_mode': 'atomic',
                'profile_sha256': report.sha(raw),
                'manifest_sha256': report.sha((directory / manifest_name).read_bytes()),
                'expected_statements': 7, 'observed_statements': observed,
                'aggregate_statements': None})

        # A valid normal profile has a positive mixed observation, but no
        # reviewed Node block. Repeated coordinates must count only once.
        mixed = unreviewed + '/sample.go'
        normal = (f'mode: atomic\n{mixed}:2.1,3.1 11 4\n'
                  f'{mixed}:2.1,3.1 11 0\n').encode()
        (fixture.node_dir / 'coverage-input.cover').write_bytes(normal)
        fixtures.store(fixture.node_dir / 'input.json', {
            'status': 'bound', 'profile_before': 'absent',
            'primary_outcome': 'success', 'profile_sha256': report.sha(normal)})
        bind(fixture.node_dir, normal, 'node-direct-r25.json',
             'node-direct-r25-bound-manifest.json', {'covered': 0, 'total': 0})

        # Race sees only the second reviewed block, with repeated zero and
        # positive counters. The first weight is still absent in this mode.
        node_file = fixture.node_file
        race = (f'mode: atomic\n{node_file}:4.1,5.1 5 0\n'
                f'{node_file}:4.1,5.1 5 7\n').encode()
        (fixture.race_dir / 'coverage.out').write_bytes(race)
        fixtures.store(fixture.race_report / 'provenance.json', {
            'run_mode': 'race', 'subject': fixture.subject,
            'selector_review_sha256': '8bd94f4dd795da74a2522c6d5b006bca1310fa352c9d1b1c818b678f449b7554',
            'selector_manifest_sha256': report.sha(fixture.selectors),
            'census_sha256': report.sha(fixture.nt), 'profile_sha256': report.sha(race),
            'test_exit': 0, 'status': 'caller_receipt_matched'})
        bind(fixture.race_report, race, 'report.json', 'bound-manifest.json',
             {'covered': 5, 'total': 5})
        fixture.common()

        value = fixture.build()
        rows = {row['package']: row for row in value['packages']}
        node = rows[fixture.node_pkg]
        unknown = rows[unreviewed]
        self.assertEqual('partial_reviewed_subset', node['attribution'])
        self.assertEqual({
            'expected_statements': 7, 'observed_statements': None,
            'missing_statements': 7, 'complete_subset_statements': None}, node['normal'])
        self.assertEqual({
            'expected_statements': 7, 'observed_statements': {'covered': 5, 'total': 5},
            'missing_statements': 2, 'complete_subset_statements': None}, node['race'])
        self.assertIsNone(node['node_primary_mixed_normal'])

        self.assertEqual('unreviewed', unknown['attribution'])
        self.assertEqual({'covered': 11, 'total': 11}, unknown['node_primary_mixed_normal'])
        null = {'expected_statements': None, 'observed_statements': None,
                'missing_statements': None, 'complete_subset_statements': None}
        self.assertEqual(null, unknown['normal'])
        self.assertEqual(null, unknown['race'])

        # The mode totals are independent: 3 of 3 known observations in
        # normal (Common), and 5 of 8 in race (Node 5, Common 0 of 3).
        self.assertEqual({
            'expected_statements': 10, 'observed_statements': {'covered': 3, 'total': 3},
            'missing_statements': 7, 'complete_subset_statements': None},
            value['attributed_subset']['normal'])
        self.assertEqual({
            'expected_statements': 10, 'observed_statements': {'covered': 5, 'total': 8},
            'missing_statements': 2, 'complete_subset_statements': None},
            value['attributed_subset']['race'])
        self.assertTrue(all(row['status'] == 'bound_partial_diagnostic'
                            for row in value['inputs'].values()))
        self.assertEqual('NOT_EVALUATED', value['status'])
        self.assertEqual({'expected_statements': None, 'covered_statements': None,
                          'percent': None}, value['full_standard_token'])
