"""Synthetic mixed measurements and older source-matched receipts stay separate."""
import unittest

import attribution
import consolidation
import producer
import report
from test_attribution import COMMON, DIGEST, EXTRA, NODE
from test_consolidation import inputs


class ModeReceiptProvenanceTests(unittest.TestCase):
    def test_zero_missing_and_historical_only_stay_distinct_per_mode(self):
        review, census, retained, audit = inputs()
        retained['selections'] = {}
        # The older receipt has an explicitly recorded zero on a reviewed
        # coordinate in normal; race has a hit on an unreviewed coordinate.
        # Both are source-matched metadata, not current observations.
        retained['retained_prior'] = {
            'older-label': {
                'package': COMMON,
                'modes': {
                    'normal': {'blocks': [
                        {'id': [COMMON + '/label.go', 1, 1, 2, 1, 2], 'count': 0},
                    ]},
                    'race': {'blocks': [
                        {'id': [COMMON + '/label.go', 5, 1, 6, 1, 3], 'count': 1},
                    ]},
                },
            },
        }

        consolidation.check_identity(review, census, retained, audit, 'd' * 64, 'c' * 64)
        history = consolidation.reconcile(
            review, census, retained, audit, lambda pkg, source: DIGEST)
        self.assertEqual('NOT_EVALUATED', history['status'])
        self.assertIsNone(history['full_ordinary_only_denominator'])
        self.assertIsNone(history['aggregate_coverage'])

        for mode, measured, absent, overlap in (
            ('normal', NODE, EXTRA, 1),
            ('race', EXTRA, NODE, 0),
        ):
            with self.subTest(mode=mode):
                # One actually measured package with all zero counters
                # including the zero-width metadata coordinate. The other
                # package and the older-receipt package have no current rows.
                current = report.parse_profile((
                    f'mode: atomic\n{measured}/label.go:1.1,2.1 2 0\n'
                    f'{measured}/label.go:3.1,3.1 0 0\n'
                    f'{measured}/label.go:5.1,6.1 3 0\n'
                ).encode())
                actual = {
                    pkg: producer.package_measure(
                        attribution.metadata_blocks(census['mode'][mode][pkg], pkg),
                        current, pkg)
                    for pkg in (NODE, EXTRA, COMMON)
                }
                zero = actual[measured]
                self.assertEqual('complete', zero['observation_status'])
                self.assertEqual({'covered': 0, 'total': 5}, zero['observed_statements'])
                self.assertEqual({'covered': 0, 'total': 5}, zero['complete_subset_statements'])
                self.assertEqual(3, zero['observed_blocks'])
                for pkg in (absent, COMMON):
                    self.assertEqual('not_observed', actual[pkg]['observation_status'])
                    self.assertEqual(5, actual[pkg]['expected_statements'])
                    self.assertEqual(3, actual[pkg]['missing_blocks'])
                    self.assertIsNone(actual[pkg]['observed_statements'])
                    self.assertIsNone(actual[pkg]['complete_subset_statements'])

                subtotal = producer.aggregate(list(actual.values()))
                self.assertEqual(15, subtotal['known_expected_statements'])
                self.assertEqual(1, subtotal['packages_complete'])
                self.assertEqual({'covered': 0, 'total': 5}, subtotal['observed_statements'])
                self.assertIsNone(subtotal['complete_statements'])

                row = history['modes'][mode]
                self.assertIsNone(row['coverage'])
                self.assertEqual(2, row['source_matched_functions'])
                old = next(fn for fn in row['reviewed_functions'] if fn['package'] == COMMON)
                self.assertTrue(old['current_source_matches'])
                self.assertFalse(old['current_compiler_remeasured'])
                self.assertEqual(2, old['prior_reviewed_statements'])
                self.assertIsNone(old['current_coverage'])
                self.assertEqual(['retained:older-label'] if overlap else [],
                                 old['overlapping_receipts'])
                self.assertEqual([{
                    'receipt': 'retained:older-label', 'package': COMMON,
                    'receipt_classification': 'direct', 'reviewed_overlap_blocks': overlap,
                    'coverage_adopted': False,
                    'reason': ('overlap_requires_current_review_and_eligible_producer'
                               if overlap else 'outside_reviewed_manifest'),
                }], row['receipt_dispositions'])
