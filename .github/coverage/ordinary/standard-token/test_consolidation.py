"""Synthetic tests for the read-only cross-receipt join."""
import copy
import unittest

import consolidation as c
import report
from test_attribution import NODE, EXTRA, COMMON, DIGEST, compiler, joined


def inputs():
    review = joined()
    census = compiler()
    review['compiler_manifest_sha256'] = 'c' * 64
    review['common_effective_module_lock_verified'] = True
    observed = {'id': [EXTRA + '/label.go', 1, 1, 2, 1, 2], 'count': 1}
    selection = {'package': EXTRA, 'classification': 'direct', 'subject': '1' * 40, 'modes': {
        mode: {'mode': mode, 'functions': [{'blocks': [copy.deepcopy(observed)]}]} for mode in c.MODES}}
    value = {'z2_subject': review['subject'], 'z2_manifest_sha256': 'c' * 64,
             'z2_review_sha256': 'd' * 64, 'node_subject': '1' * 40,
             'common_subject': report.PIN, 'selections': {'extra': selection}, 'retained_prior': {}}
    audit = {'older_census_subject': review['subject'], 'subject': value['node_subject'], 'common_subject': report.PIN,
             'rows': [{'package': pkg} for pkg in (NODE, EXTRA, COMMON)]}
    return review, census, value, audit


class ConsolidationTests(unittest.TestCase):
    def test_disjoint_observation_has_no_credit(self):
        args = inputs()
        c.check_identity(*args, 'd' * 64, 'c' * 64)
        result = c.reconcile(*args, lambda p, f: DIGEST)
        self.assertEqual('NOT_EVALUATED', result['status'])
        self.assertIsNone(result['full_ordinary_only_denominator'])
        self.assertIsNone(result['aggregate_coverage'])
        for mode in c.MODES:
            v = result['modes'][mode]
            self.assertEqual(2, v['source_matched_functions'])
            self.assertEqual([NODE, COMMON], [f['package'] for f in v['reviewed_functions']])
            self.assertTrue(all(f['current_coverage'] is None and not f['current_compiler_remeasured'] for f in v['reviewed_functions']))
            self.assertEqual(0, v['receipt_dispositions'][0]['reviewed_overlap_blocks'])
            self.assertFalse(v['receipt_dispositions'][0]['coverage_adopted'])
            self.assertIsNone(v['coverage'])

    def test_source_mismatch_and_overlap_do_not_adopt(self):
        review, census, value, audit = inputs()
        sel = value['selections']['extra']
        sel['package'] = NODE
        for row in sel['modes'].values():
            row['functions'][0]['blocks'][0]['id'][0] = NODE + '/label.go'
        result = c.reconcile(review, census, value, audit, lambda p, f: 'b' * 64 if p == NODE else DIGEST)
        for mode in c.MODES:
            v = result['modes'][mode]
            self.assertEqual(1, v['source_matched_functions'])
            self.assertFalse(v['reviewed_functions'][0]['current_source_matches'])
            self.assertEqual(['extra'], v['reviewed_functions'][0]['overlapping_receipts'])
            self.assertEqual(1, v['receipt_dispositions'][0]['reviewed_overlap_blocks'])
            self.assertFalse(v['receipt_dispositions'][0]['coverage_adopted'])
            self.assertIsNone(v['reviewed_functions'][0]['current_coverage'])

    def test_retained_receipts_do_not_adopt_or_merge(self):
        review, census, value, audit = inputs()
        rows = {mode: {'blocks': copy.deepcopy(row['functions'][0]['blocks'])}
                for mode, row in value['selections']['extra']['modes'].items()}
        value['retained_prior']['separate'] = {'package': EXTRA, 'modes': rows}
        result = c.reconcile(review, census, value, audit, lambda p, f: DIGEST)
        for mode in c.MODES:
            self.assertEqual(['extra', 'retained:separate'], [r['receipt'] for r in result['modes'][mode]['receipt_dispositions']])
            self.assertTrue(all(not r['coverage_adopted'] for r in result['modes'][mode]['receipt_dispositions']))

    def test_reject_bad_identity(self):
        for key, value in [('z2_subject', 'wrong'), ('z2_review_sha256', 'wrong'), ('common_subject', 'wrong')]:
            args = inputs()
            args[2][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.check_identity(*args, 'd' * 64, 'c' * 64)

    def test_reject_bad_observation_and_roster(self):
        for defect in ('duplicate', 'width', 'mode', 'subject', 'count', 'roster', 'review_total'):
            review, census, value, audit = inputs()
            mode = value['selections']['extra']['modes']['normal']
            blocks = mode['functions'][0]['blocks']
            if defect == 'duplicate':
                blocks.append(copy.deepcopy(blocks[0]))
            elif defect == 'width':
                blocks[0]['id'][-1] = 3
            elif defect == 'mode':
                mode['mode'] = 'race'
            elif defect == 'subject':
                value['selections']['extra']['subject'] = 'wrong'
            elif defect == 'count':
                blocks[0]['count'] = -1
            elif defect == 'roster':
                audit['rows'].pop()
            else:
                review['modes']['normal']['reviewed_source_bound_statements'] += 1
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                c.reconcile(review, census, value, audit, lambda p, f: DIGEST)


if __name__ == '__main__':
    unittest.main()
