"""Pure source-binding and attribution fixture tests."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import attribution as a
import report

NODE = report.NODE + '/sample'
EXTRA = report.NODE + '/extra'
COMMON = report.COMMON + '/labels'
DIGEST = 'a' * 64
ROSTER = {'node': [NODE, EXTRA], 'common': [COMMON]}


def manifest(pkg):
    return {'source': pkg.split('/')[3] + '/label.go', 'profile_file': pkg + '/label.go', 'name': 'Label',
            'source_sha256': DIGEST, 'span': [1, 1, 4, 1],
            'blocks': [{'start': [1, 1], 'end': [2, 1], 'statements': 2}]}


def metadata(pkg):
    f = pkg + '/label.go'
    return {'status': 'metadata_present', 'sources': {f: DIGEST},
            'blocks': [[f, 1, 1, 2, 1, 2], [f, 3, 1, 3, 1, 0], [f, 5, 1, 6, 1, 3]]}


def compiler():
    return {'schema': 'provisional-compiler-roster-v1', 'subject': 'f' * 40,
            'common_module_verified': True, 'common_effective_commit': report.PIN,
            'common_archive_sum': report.SUM, 'common_go_mod_sum': report.MOD_SUM,
            'mode': {mode: {pkg: metadata(pkg) for pkg in (NODE, EXTRA, COMMON)} for mode in a.MODES}}


def joined(c=None, verified=True):
    return a.reconcile(c or compiler(), ROSTER, [manifest(NODE)], [manifest(COMMON)],
                       {NODE: ['TestLabel']}, verified)


class AttributionTests(unittest.TestCase):
    def test_exact_reviewed_subset_and_unreviewed_remainder(self):
        value = joined()
        self.assertEqual('NOT_EVALUATED', value['status'])
        self.assertIsNone(value['full_ordinary_only_denominator'])
        self.assertEqual(4, value['reviewed_template_statements'])
        for mode in a.MODES:
            x = value['modes'][mode]
            self.assertEqual((3, 2, 1, 2, 2, 4, 4), tuple(x[k] for k in (
                'packages_requested', 'packages_with_reviewed_subset', 'packages_without_reviewed_subset',
                'reviewed_source_bound_functions', 'reviewed_source_bound_blocks', 'reviewed_source_bound_statements',
                'reviewed_nominal_provenance_statements')))
            rows = {r['package']: r for r in x['packages']}
            self.assertEqual(3, rows[NODE]['unresolved_mixed_statements'])
            self.assertEqual(5, rows[EXTRA]['unresolved_mixed_statements'])
            self.assertEqual('unreviewed', rows[EXTRA]['status'])
            self.assertIsNone(rows[EXTRA]['reviewed_source_bound_statements'])
            self.assertEqual([], rows[EXTRA]['functions'])
            self.assertEqual(['race'], rows[NODE]['nominal_selector_provenance']['producer_modes'])
        self.assertEqual(2, value['modes']['normal']['explicit_nominal_selector_scope_statements'])
        self.assertEqual(4, value['modes']['race']['explicit_nominal_selector_scope_statements'])

    def test_source_mismatch_and_extra_positive_compiler_block(self):
        c = compiler()
        c['mode']['normal'][NODE]['sources'][NODE + '/label.go'] = 'b' * 64
        c['mode']['race'][NODE]['blocks'].append([NODE + '/label.go', 3, 1, 5, 1, 1])
        value = joined(c)
        for mode, status in [('normal', 'reviewed_source_mismatch'), ('race', 'reviewed_compiler_blocks_mismatch')]:
            row = value['modes'][mode]['packages'][0]
            self.assertEqual(status, row['functions'][0]['status'])
            self.assertIsNone(row['functions'][0]['reviewed_blocks'])
            self.assertIsNone(row['reviewed_source_bound_statements'])
            self.assertEqual(2, value['modes'][mode]['reviewed_source_bound_statements'])

    def test_unknown_census_and_unverified_common_are_not_reclassified(self):
        c = compiler()
        c['common_archive_sum'] = 'wrong'
        c['mode']['normal'][NODE] = {'status': 'unavailable'}
        value = joined(c, verified=False)
        self.assertFalse(value['common_effective_module_lock_verified'])
        self.assertFalse(value['node_race_selector_lock_verified'])
        self.assertEqual(0, value['modes']['normal']['reviewed_source_bound_statements'])
        self.assertEqual(2, value['modes']['race']['reviewed_source_bound_statements'])
        self.assertEqual(0, value['modes']['race']['existing_producer_scope_statements'])
        row = value['modes']['normal']['packages'][0]
        self.assertIsNone(row['unresolved_mixed_statements'])
        self.assertEqual('compiler_census_unavailable', row['status'])

    def test_inconsistent_metadata_rejected(self):
        for change in ('duplicate', 'outside', 'roster'):
            c = compiler()
            row = c['mode']['normal'][NODE]
            if change == 'duplicate':
                row['blocks'].append(copy.deepcopy(row['blocks'][0]))
            elif change == 'outside':
                row['blocks'][0][0] = EXTRA + '/label.go'
            else:
                del c['mode']['normal'][EXTRA]
            with self.subTest(change=change), self.assertRaises(ValueError):
                joined(c)

    def test_locked_review_and_exact_selector_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'one.go'; path.write_bytes(b'package fixture\n')
            selectors = {'review_sha256': a.RACE_REVIEW, 'census_sha256': a.NODE_CENSUS,
                         'files': {'one.go': report.sha(path.read_bytes())},
                         'packages': [{'package': 'sample', 'roots': ['TestLabel']}]}
            raw = json.dumps(selectors).encode(); (root / 'review.json').write_bytes(raw)
            self.assertEqual(selectors, a.locked_json(root, 'review.json', report.sha(raw)))
            with self.assertRaises(ValueError):
                a.locked_json(root, 'review.json', DIGEST)
            self.assertEqual(({NODE: ['TestLabel']}, True), a.selector_lock(root, selectors))
            path.write_bytes(b'changed')
            self.assertEqual(({}, False), a.selector_lock(root, selectors))
            selectors['files'] = {'../one.go': DIGEST}
            self.assertEqual(({}, False), a.selector_lock(root, selectors))


if __name__ == '__main__':
    unittest.main()
