"""Detached static representation proposals, separate from reviewed attribution."""
import copy
import unittest
from pathlib import Path
from unittest.mock import patch

import attribution as a
from test_attribution import COMMON, DIGEST, EXTRA, NODE, ROSTER, compiler, joined, manifest


def fixture():
    other = manifest(COMMON)
    other.update(name='OtherLabel', span=[5, 1, 6, 1],
                 blocks=[{'start': [5, 1], 'end': [6, 1], 'statements': 3}])
    return {'schema': 'detached-token-representation-proposals-v1',
            'functions': [manifest(EXTRA), other]}


def reconcile(c=None, proposals=None, common_verified=True):
    return a.representation_proposals(c or compiler(), ROSTER, [manifest(NODE), manifest(COMMON)],
                                      proposals or fixture(), common_verified)


class RepresentationProposalTests(unittest.TestCase):
    def test_separate_proposal_inventory_keeps_review_and_denominator(self):
        c = compiler()
        before = joined(c)
        result = reconcile(c)
        self.assertEqual(before, joined(c))
        self.assertEqual('PROPOSED_NOT_ADMITTED', result['status'])
        self.assertIsNone(result['coverage'])
        self.assertIsNone(result['ordinary_only_denominator'])
        for mode in a.MODES:
            row = result['modes'][mode]
            self.assertEqual((2, 2, 2, 5), tuple(row[k] for k in
                             ('proposed_functions', 'source_bound_functions', 'known_source_bound_blocks',
                              'known_source_bound_statements')))
            self.assertTrue(all(f['status'] == 'proposed_source_bound' for f in row['functions']))
            self.assertEqual(4, before['modes'][mode]['reviewed_source_bound_statements'])

    def test_absent_and_stale_census_remain_unknown(self):
        c = compiler()
        c['mode']['normal'][EXTRA] = {'status': 'unavailable'}
        c['mode']['normal'][COMMON]['sources'][COMMON + '/label.go'] = 'b' * 64
        c['mode']['race'][EXTRA]['blocks'][0][-1] = 9
        result = reconcile(c)
        normal = result['modes']['normal']
        race = result['modes']['race']
        self.assertEqual(['compiler_census_unavailable', 'reviewed_source_mismatch'],
                         [f['status'] for f in normal['functions']])
        self.assertEqual(['reviewed_compiler_blocks_mismatch', 'proposed_source_bound'],
                         [f['status'] for f in race['functions']])
        self.assertEqual(0, normal['source_bound_functions'])
        self.assertIsNone(normal['known_source_bound_blocks'])
        self.assertIsNone(normal['known_source_bound_statements'])
        self.assertIsNone(normal['functions'][0]['source_bound_blocks'])
        self.assertEqual(3, race['known_source_bound_statements'])

    def test_unverified_common_not_bound(self):
        result = reconcile(common_verified=False)
        for mode in a.MODES:
            row = result['modes'][mode]
            self.assertEqual(1, row['source_bound_functions'])
            self.assertEqual(2, row['known_source_bound_statements'])
            self.assertEqual('common_source_lock_unverified', row['functions'][1]['status'])
            self.assertIsNone(row['functions'][1]['source_bound_statements'])

    def test_build_attaches_only_separate_locked_proposal_table(self):
        c = compiler()
        before = joined(c)
        by_name = {
            'node-direct-r25.json': {'functions': [manifest(NODE)]},
            'common-direct/census.json': {'functions': [manifest(COMMON)], 'common_commit': a.report.PIN},
            'node-direct-race/selectors-r28.json': {},
            'representation-proposals.json': fixture(),
        }
        with patch.object(a, 'locked_json', side_effect=lambda _root, name, _digest: by_name[name]) as load, \
             patch.object(a, 'selector_lock', return_value=({NODE: ['TestLabel']}, True)):
            value = a.build(Path('.'), c, 'c' * 64, ROSTER)
        self.assertEqual(before['modes'], value['modes'])
        self.assertIsNone(value['full_ordinary_only_denominator'])
        self.assertEqual('c' * 64, value['compiler_manifest_sha256'])
        table = value['detached_representation_proposals']
        self.assertEqual(a.REPRESENTATION_PROPOSALS, table['manifest_sha256'])
        self.assertEqual('PROPOSED_NOT_ADMITTED', table['status'])
        self.assertEqual(a.REPRESENTATION_PROPOSALS, load.call_args.args[-1])

    def test_duplicate_overlap_and_schema_rejected(self):
        valid = fixture()
        for bad in (
            dict(valid, schema='wrong'),
            dict(valid, functions=[manifest(NODE)]),
            dict(valid, functions=valid['functions'] + [copy.deepcopy(valid['functions'][0])]),
            dict(valid, functions=[dict(manifest(EXTRA), source_sha256='not-digest')]),
        ):
            with self.subTest(schema=bad['schema']), self.assertRaises(ValueError):
                reconcile(proposals=bad)


if __name__ == '__main__':
    unittest.main()
