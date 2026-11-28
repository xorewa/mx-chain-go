"""Direct script entry and Git wrapper checks with synthetic reporting inputs only."""
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import call, patch

import consolidation
import report
from test_attribution import COMMON, NODE
from test_consolidation import inputs


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def store(path, value):
    raw = (json.dumps(value, sort_keys=True) + '\n').encode()
    path.write_bytes(raw)
    return sha(raw)


class DiagnosticScriptEntryTests(unittest.TestCase):
    def test_consolidation_script_forwards_git_read_arguments(self):
        review, compiler, consolidated, audit = inputs()
        sources = {NODE: b'synthetic node label\n', COMMON: b'synthetic common label\n'}
        locks = {'go.mod': b'synthetic module\n', 'go.sum': b'synthetic sums\n'}
        consolidated.update(node_tree='2' * 40, common_tree='3' * 40)
        compiler.update(go_mod_sha256=sha(locks['go.mod']), go_sum_sha256=sha(locks['go.sum']))
        for mode in ('normal', 'race'):
            for pkg, raw in sources.items():
                compiler['mode'][mode][pkg]['sources'][pkg + '/label.go'] = sha(raw)
                row = next(x for x in review['modes'][mode]['packages'] if x['package'] == pkg)
                row['functions'][0]['source_sha256'] = sha(raw)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node, common = root / 'node', root / 'common'
            node.mkdir()
            common.mkdir()
            compiler_path, review_path = root / 'compiler.json', root / 'review.json'
            value_path, audit_path = root / 'consolidated.json', root / 'audit.json'
            compiler_sha = store(compiler_path, compiler)
            review['compiler_manifest_sha256'] = compiler_sha
            review_sha = store(review_path, review)
            consolidated.update(z2_manifest_sha256=compiler_sha, z2_review_sha256=review_sha)
            value_sha = store(value_path, consolidated)
            audit_sha = store(audit_path, audit)
            output = root / 'result.json'

            responses = {}
            for checkout, subject, tree in (
                    (node, consolidated['node_subject'], consolidated['node_tree']),
                    (common, consolidated['common_subject'], consolidated['common_tree'])):
                for args, raw in ((('rev-parse', 'HEAD'), subject.encode() + b'\n'),
                                  (('rev-parse', 'HEAD^{tree}'), tree.encode() + b'\n'),
                                  (('status', '--porcelain', '--untracked-files=all'), b'')):
                    responses[('git', '-C', str(checkout), *args)] = raw
            node_label = consolidated['node_subject'] + ':sample/label.go'
            common_label = consolidated['common_subject'] + ':labels/label.go'
            for name, raw in locks.items():
                responses[('git', '-C', str(node), 'show', consolidated['node_subject'] + ':' + name)] = raw
            responses[('git', '-C', str(node), 'show', node_label)] = sources[NODE]
            responses[('git', '-C', str(common), 'show', common_label)] = sources[COMMON]

            argv = ['consolidation.py', '--review', str(review_path), '--compiler', str(compiler_path),
                    '--consolidated', str(value_path), '--roster-audit', str(audit_path),
                    '--node-root', str(node), '--common-root', str(common), '--output', str(output)]
            with patch.object(sys, 'argv', argv), patch.object(
                    subprocess, 'check_output', side_effect=lambda args: responses[tuple(args)]) as git:
                runpy.run_path(str(Path(consolidation.__file__).resolve()), run_name='__main__')

            expected = [call(list(args)) for args in responses]
            expected += [call(['git', '-C', str(node), 'show', node_label]),
                         call(['git', '-C', str(common), 'show', common_label])]
            self.assertEqual(expected, git.call_args_list)
            self.assertEqual([], list(node.iterdir()))
            self.assertEqual([], list(common.iterdir()))
            data = json.loads(output.read_bytes())
            self.assertEqual('NOT_EVALUATED', data['status'])
            self.assertIsNone(data['full_ordinary_only_denominator'])
            self.assertIsNone(data['aggregate_coverage'])
            self.assertEqual({'review_sha256': review_sha, 'compiler_sha256': compiler_sha,
                              'consolidated_sha256': value_sha, 'roster_audit_sha256': audit_sha}, data['inputs'])
            for mode in ('normal', 'race'):
                row = data['modes'][mode]
                self.assertEqual(2, row['source_matched_functions'])
                self.assertIsNone(row['coverage'])
                self.assertEqual([NODE, COMMON], [f['package'] for f in row['reviewed_functions']])
                self.assertTrue(all(f['current_coverage'] is None for f in row['reviewed_functions']))
                self.assertEqual([('extra', 0, False)], [
                    (r['receipt'], r['reviewed_overlap_blocks'], r['coverage_adopted'])
                    for r in row['receipt_dispositions']])

    def test_report_script_preserves_unmeasured_scope(self):
        subject = 'c' * 40
        pkg = report.NODE + '/synthetic_display'
        common = report.COMMON + '/synthetic_display'
        label = b'synthetic display source\n'
        source_name = 'synthetic_display/label.go'
        template = {'functions': [{'source': source_name, 'source_sha256': sha(label),
                    'profile_file': pkg + '/label.go', 'name': 'DisplayLabel', 'span': [1, 1, 3, 1],
                    'blocks': [{'start': [1, 1], 'end': [2, 1], 'statements': 2}]}]}
        roster = {'schema': 'standard-token-provisional-roster-v1', 'node': [pkg], 'common': [common]}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = Path(report.__file__).resolve()
            source = root / source_name
            source.parent.mkdir()
            source.write_bytes(label)
            checkout = root / '.github/coverage/ordinary'
            for name, value in (('node-direct-r25.json', template), ('common-direct/census.json', {'functions': []}),
                                ('node-direct-race/selectors-r28.json', {})):
                path = checkout / name
                path.parent.mkdir(parents=True, exist_ok=True)
                store(path, value)
            roster_path = root / 'roster.json'
            store(roster_path, roster)
            output = root / 'report.json'
            original_read = Path.read_bytes

            def synthetic_roster(path):
                return original_read(roster_path if path == script.parent / 'roster.json' else path)

            argv = ['report.py', '--checkout', str(root), '--subject', subject, '--output', str(output)]
            with patch.object(sys, 'argv', argv), patch.object(Path, 'read_bytes', synthetic_roster), \
                 patch.object(subprocess, 'check_output', return_value=subject + '\n') as git:
                runpy.run_path(str(script), run_name='__main__')
            git.assert_called_once_with(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True)
            result = json.loads(output.read_bytes())
            self.assertEqual(subject, result['subject'])
            self.assertEqual('NOT_EVALUATED', result['status'])
            self.assertEqual({'expected_statements': None, 'covered_statements': None, 'percent': None},
                             result['full_standard_token'])
            self.assertEqual([pkg, common], [r['package'] for r in result['packages']])
            self.assertTrue(all(x == {'status': 'not_supplied', 'profile_sha256': None}
                                for x in result['inputs'].values()))
            for mode in ('normal', 'race'):
                self.assertEqual({'expected_statements': 2, 'observed_statements': None,
                                  'missing_statements': 2, 'complete_subset_statements': None},
                                 result['attributed_subset'][mode])
                self.assertIsNone(result['packages'][1][mode]['expected_statements'])
            self.assertEqual(label, source.read_bytes())
