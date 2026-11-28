"""Detached complete-zero and cross-package arithmetic for the report."""
import hashlib
import unittest

import report
import test_report as fixtures


class CrossPackageReportingTests(unittest.TestCase):
    def test_same_coordinates_in_distinct_packages_keep_complete_zero(self):
        fixture = fixtures.BoundFixtureTests('test_full_subset_is_not_gate')
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()

        # The two Node files deliberately have identical names and source
        # coordinates, but different packages and independent weights.
        second_pkg = report.NODE + '/labels_second'
        second_file = second_pkg + '/fixture.go'
        relative = 'labels_second/fixture.go'
        source = b'second display fixture'
        (fixture.root / relative).parent.mkdir()
        (fixture.root / relative).write_bytes(source)
        fixture.nf.append(fixture.function(
            second_file, relative, hashlib.sha256(source).hexdigest(), 5))
        fixture.nt = fixtures.encoded({'functions': fixture.nf})
        fixture.roster['node'].insert(1, second_pkg)
        mixed_pkg = fixture.roster['node'][-1]

        def digest(data):
            return hashlib.sha256(data).hexdigest()

        def bind(directory, raw, functions, report_name, manifest_name,
                 covered, total):
            fixtures.store(directory / manifest_name, {
                'profile_sha256': digest(raw), 'functions': functions})
            # Literal producer claims, independent of report.tally.
            fixtures.store(directory / report_name, {
                'profile_status': 'present', 'profile_mode': 'atomic',
                'profile_sha256': digest(raw),
                'manifest_sha256': digest((directory / manifest_name).read_bytes()),
                'expected_statements': total,
                'observed_statements': {'covered': covered, 'total': total},
                'aggregate_statements': {'covered': covered, 'total': total}})

        normal = (f'mode: atomic\n{second_file}:2.1,3.1 5 0\n'
                  f'{fixture.node_file}:2.1,3.1 2 0\n'
                  f'{mixed_pkg}/fixture.go:2.1,3.1 11 1\n').encode()
        (fixture.node_dir / 'coverage-input.cover').write_bytes(normal)
        fixtures.store(fixture.node_dir / 'input.json', {
            'status': 'bound', 'profile_before': 'absent',
            'primary_outcome': 'success', 'profile_sha256': digest(normal)})
        bind(fixture.node_dir, normal, fixture.nf, 'node-direct-r25.json',
             'node-direct-r25-bound-manifest.json', 0, 7)

        race = (f'mode: atomic\n{fixture.node_file}:2.1,3.1 2 1\n'
                f'{second_file}:2.1,3.1 5 0\n').encode()
        (fixture.race_dir / 'coverage.out').write_bytes(race)
        fixtures.store(fixture.race_report / 'provenance.json', {
            'run_mode': 'race', 'subject': fixture.subject,
            'selector_review_sha256': '8bd94f4dd795da74a2522c6d5b006bca1310fa352c9d1b1c818b678f449b7554',
            'selector_manifest_sha256': digest(fixture.selectors),
            'census_sha256': digest(fixture.nt), 'profile_sha256': digest(race),
            'test_exit': 0, 'status': 'caller_receipt_matched'})
        bind(fixture.race_report, race, fixture.nf, 'report.json',
             'bound-manifest.json', 2, 7)

        summary = {
            'common_commit': report.PIN, 'module': report.MOD, 'version': report.VERSION,
            'archive_sum': report.SUM, 'go_mod_sum': report.MOD_SUM,
            'census_sha256': digest(fixture.ct), 'package': fixture.common_pkg,
            'selected_roots': ['TestComputeTokenIdentifier', 'TestExtractTokenAndNonce'],
            'expected_statements': 3}
        for mode, hits, covered in [('normal', 0, 0), ('race', 1, 3)]:
            raw = f'mode: atomic\n{fixture.common_file}:2.1,3.1 3 {hits}\n'.encode()
            (fixture.common_dir / (mode + '.cover')).write_bytes(raw)
            bind(fixture.common_dir, raw, fixture.cf, mode + '.report.json',
                 mode + '.manifest.json', covered, 3)
            summary[mode] = {'status': 'measured', 'test_exit': 0,
                             'profile_sha256': digest(raw),
                             'statements': {'covered': covered, 'total': 3}}
        fixtures.store(fixture.common_dir / 'summary.json', summary)

        value = fixture.build()
        rows = {row['package']: row for row in value['packages']}

        def complete(covered, total):
            return {'expected_statements': total,
                    'observed_statements': {'covered': covered, 'total': total},
                    'missing_statements': 0,
                    'complete_subset_statements': {'covered': covered, 'total': total}}

        # All reviewed blocks were present in both modes. Normal genuinely
        # measured zero, including Common; the 11 mixed hits are not credit.
        self.assertEqual(complete(0, 10), value['attributed_subset']['normal'])
        self.assertEqual(complete(5, 10), value['attributed_subset']['race'])
        for pkg, total, race_covered in [(fixture.node_pkg, 2, 2),
                                         (second_pkg, 5, 0),
                                         (fixture.common_pkg, 3, 3)]:
            with self.subTest(package=pkg):
                self.assertEqual('partial_reviewed_subset', rows[pkg]['attribution'])
                self.assertEqual(complete(0, total), rows[pkg]['normal'])
                self.assertEqual(complete(race_covered, total), rows[pkg]['race'])
        self.assertEqual({'covered': 0, 'total': 2}, rows[fixture.node_pkg]['node_primary_mixed_normal'])
        self.assertEqual({'covered': 0, 'total': 5}, rows[second_pkg]['node_primary_mixed_normal'])
        self.assertIsNone(rows[fixture.common_pkg]['node_primary_mixed_normal'])
        self.assertEqual({'covered': 11, 'total': 11}, rows[mixed_pkg]['node_primary_mixed_normal'])
        for mode in ('normal', 'race'):
            self.assertEqual('unreviewed', rows[mixed_pkg]['attribution'])
            self.assertTrue(all(v is None for v in rows[mixed_pkg][mode].values()))
        self.assertTrue(all(entry['status'] == 'bound_partial_diagnostic'
                            for entry in value['inputs'].values()))
        self.assertEqual('NOT_EVALUATED', value['status'])
        self.assertEqual({'expected_statements': None, 'covered_statements': None,
                          'percent': None}, value['full_standard_token'])
