"""Successful offline consolidation CLI with synthetic Git and receipt inputs."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch

import consolidation as c
from test_attribution import COMMON, NODE
from test_consolidation import inputs


class ConsolidationCliTests(unittest.TestCase):
    def test_cli_writes_source_bound_unadmitted_mode_receipts(self):
        def digest(raw):
            return hashlib.sha256(raw).hexdigest()

        review, compiler, value, audit = inputs()
        node_source, common_source = b'synthetic node label\n', b'synthetic common label\n'
        module, sums = b'synthetic module identity\n', b'synthetic sum identity\n'
        node_tree, common_tree = '2' * 40, '3' * 40
        value.update(node_tree=node_tree, common_tree=common_tree)
        compiler.update(go_mod_sha256=digest(module), go_sum_sha256=digest(sums))

        for mode in ('normal', 'race'):
            for pkg, raw in ((NODE, node_source), (COMMON, common_source)):
                compiler['mode'][mode][pkg]['sources'][pkg + '/label.go'] = digest(raw)
                reviewed = next(row for row in review['modes'][mode]['packages']
                                if row['package'] == pkg)
                reviewed['functions'][0]['source_sha256'] = digest(raw)

        def direct(pkg, subject, normal_reviewed):
            modes = {}
            for mode, reviewed in (('normal', normal_reviewed), ('race', not normal_reviewed)):
                coordinate = ([pkg + '/label.go', 1, 1, 2, 1, 2] if reviewed else
                              [pkg + '/label.go', 5, 1, 6, 1, 3])
                modes[mode] = {'mode': mode, 'functions': [{'blocks': [
                    {'id': coordinate, 'count': 1},
                ]}]}
            return {'package': pkg, 'subject': subject,
                    'classification': 'direct', 'modes': modes}

        value['selections'] = {
            'node-display': direct(NODE, value['node_subject'], True),
            'common-display': direct(COMMON, value['common_subject'], False),
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node_root, common_root = root / 'node', root / 'common'
            node_root.mkdir()
            common_root.mkdir()

            files = {}

            def store(name, data):
                path = root / (name + '.json')
                raw = json.dumps(data, sort_keys=True).encode('utf-8') + b'\n'
                path.write_bytes(raw)
                files[path] = raw
                return path, digest(raw)

            compiler_path, compiler_sha = store('compiler', compiler)
            review['compiler_manifest_sha256'] = compiler_sha
            review_path, review_sha = store('review', review)
            value.update(z2_manifest_sha256=compiler_sha, z2_review_sha256=review_sha)
            consolidated_path, consolidated_sha = store('consolidated', value)
            audit_path, audit_sha = store('audit', audit)
            output = root / 'output.json'

            # All Git reads are synthetic, including the two clean tree identities.
            # No actual source repository is opened by this fixture.
            responses = {}
            identity_calls = []
            for checkout, subject, tree in ((node_root, value['node_subject'], node_tree),
                                            (common_root, value['common_subject'], common_tree)):
                for args, raw in ((('rev-parse', 'HEAD'), subject.encode() + b'\n'),
                                  (('rev-parse', 'HEAD^{tree}'), tree.encode() + b'\n'),
                                  (('status', '--porcelain', '--untracked-files=all'), b'')):
                    responses[checkout, args] = raw
                    identity_calls.append(call(checkout, *args))
            node_subject, common_subject = value['node_subject'], value['common_subject']
            node_label = node_subject + ':sample/label.go'
            common_label = common_subject + ':labels/label.go'
            responses[node_root, ('show', node_subject + ':go.mod')] = module
            responses[node_root, ('show', node_subject + ':go.sum')] = sums
            responses[node_root, ('show', node_label)] = node_source
            responses[common_root, ('show', common_label)] = common_source

            argv = ['consolidation.py', '--review', str(review_path),
                    '--compiler', str(compiler_path), '--consolidated', str(consolidated_path),
                    '--roster-audit', str(audit_path), '--node-root', str(node_root),
                    '--common-root', str(common_root), '--output', str(output)]
            with patch('sys.argv', argv), patch.object(
                    c, 'git', side_effect=lambda checkout, *args: responses[checkout, args]) as git:
                c.main()
            self.assertEqual(identity_calls + [
                call(node_root, 'show', node_subject + ':go.mod'),
                call(node_root, 'show', node_subject + ':go.sum'),
                call(node_root, 'show', node_label), call(common_root, 'show', common_label),
                call(node_root, 'show', node_label), call(common_root, 'show', common_label),
            ], git.call_args_list)

            self.assertEqual({*files, node_root, common_root, output}, set(root.iterdir()))
            self.assertTrue(all(path.read_bytes() == raw for path, raw in files.items()))
            self.assertEqual([], list(node_root.iterdir()))
            self.assertEqual([], list(common_root.iterdir()))
            data = json.loads(output.read_bytes())
            self.assertEqual('ordinary-reviewed-consolidation-diagnostic-v1', data['schema'])
            self.assertEqual('NOT_EVALUATED', data['status'])
            self.assertIsNone(data['full_ordinary_only_denominator'])
            self.assertIsNone(data['aggregate_coverage'])
            self.assertEqual((review['subject'], node_subject, common_subject),
                             (data['reviewed_subject'], data['node_subject'], data['common_subject']))
            self.assertEqual({'review_sha256': review_sha, 'compiler_sha256': compiler_sha,
                              'consolidated_sha256': consolidated_sha, 'roster_audit_sha256': audit_sha},
                             data['inputs'])
            self.assertEqual({'normal', 'race'}, set(data['modes']))
            for mode, expected in (('normal', (1, 0)), ('race', (0, 1))):
                with self.subTest(mode=mode):
                    row = data['modes'][mode]
                    self.assertEqual(2, row['source_matched_functions'])
                    self.assertIsNone(row['coverage'])
                    self.assertEqual([NODE, COMMON], [f['package'] for f in row['reviewed_functions']])
                    receipts = row['receipt_dispositions']
                    # The stored JSON has sorted keys; identify each disposition
                    # by its own receipt name, not the in-memory insertion order.
                    self.assertEqual(2, len(receipts))
                    self.assertEqual({('node-display', NODE), ('common-display', COMMON)},
                                     {(r['receipt'], r['package']) for r in receipts})
                    by_name = {r['receipt']: r for r in receipts}
                    for name, overlap in zip(('node-display', 'common-display'), expected):
                        disposition = by_name[name]
                        self.assertEqual(overlap, disposition['reviewed_overlap_blocks'])
                        self.assertEqual('direct', disposition['receipt_classification'])
                        self.assertFalse(disposition['coverage_adopted'])
                        self.assertEqual(
                            'overlap_requires_current_review_and_eligible_producer' if overlap
                            else 'outside_reviewed_manifest', disposition['reason'])
                    for function, overlap, name in zip(row['reviewed_functions'], expected,
                                                       ('node-display', 'common-display')):
                        self.assertEqual([name] if overlap else [], function['overlapping_receipts'])
                        self.assertEqual((1, 2), (function['prior_reviewed_blocks'],
                                                  function['prior_reviewed_statements']))
                        self.assertTrue(function['current_source_matches'])
                        self.assertFalse(function['current_compiler_remeasured'])
                        self.assertIsNone(function['current_coverage'])
