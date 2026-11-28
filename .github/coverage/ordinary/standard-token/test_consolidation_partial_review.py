"""Detached report join: mode-specific unavailable census and Common receipts."""
import unittest

import consolidation as c
import report
from test_attribution import COMMON, DIGEST, NODE, joined
from test_consolidation import inputs


class PartialReviewConsolidationTests(unittest.TestCase):
    def test_available_review_and_common_receipts_remain_mode_specific(self):
        _, census, value, audit = inputs()
        census['mode']['normal'][NODE] = {'status': 'unavailable'}
        review = joined(census)
        review['compiler_manifest_sha256'] = 'c' * 64
        value['selections'] = {
            'common-display': {
                'package': COMMON,
                'classification': 'shared',
                'subject': report.PIN,
                'modes': {
                    'normal': {'mode': 'normal', 'functions': [{'blocks': [
                        {'id': [COMMON + '/label.go', 5, 1, 6, 1, 3], 'count': 1},
                    ]}]},
                    'race': {'mode': 'race', 'functions': [{'blocks': [
                        {'id': [COMMON + '/label.go', 1, 1, 2, 1, 2], 'count': 1},
                    ]}]},
                },
            },
        }
        reads = []

        def source_digest(pkg, source):
            reads.append((pkg, source))
            return DIGEST

        c.check_identity(review, census, value, audit, 'd' * 64, 'c' * 64)
        result = c.reconcile(review, census, value, audit, source_digest)
        self.assertEqual('NOT_EVALUATED', result['status'])
        self.assertIsNone(result['full_ordinary_only_denominator'])
        self.assertIsNone(result['aggregate_coverage'])
        self.assertEqual([(COMMON, 'labels/label.go'), (NODE, 'sample/label.go'),
                          (COMMON, 'labels/label.go')], reads)
        for mode, expected_packages, overlaps, reason in (
            ('normal', [COMMON], 0, 'outside_reviewed_manifest'),
            ('race', [NODE, COMMON], 1, 'overlap_requires_current_review_and_eligible_producer'),
        ):
            with self.subTest(mode=mode):
                row = result['modes'][mode]
                functions = row['reviewed_functions']
                self.assertEqual(expected_packages, [f['package'] for f in functions])
                self.assertEqual(len(expected_packages), row['source_matched_functions'])
                self.assertEqual([(1, 2)] * len(expected_packages), [
                    (f['prior_reviewed_blocks'], f['prior_reviewed_statements']) for f in functions])
                self.assertEqual(['common-display'] if overlaps else [],
                                 functions[-1]['overlapping_receipts'])
                self.assertTrue(all(f['current_coverage'] is None and not
                                    f['current_compiler_remeasured'] for f in functions))
                self.assertIsNone(row['coverage'])
                self.assertEqual([{
                    'receipt': 'common-display', 'package': COMMON,
                    'receipt_classification': 'shared', 'reviewed_overlap_blocks': overlaps,
                    'coverage_adopted': False, 'reason': reason,
                }], row['receipt_dispositions'])
