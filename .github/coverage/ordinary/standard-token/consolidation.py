"""Read-only cross-receipt reconciliation; no new attribution or CI gate."""
import argparse
import json
from pathlib import Path
import subprocess

import attribution
import report

MODES = attribution.MODES


def loaded(path):
    raw = path.read_bytes()
    return json.loads(raw), report.sha(raw)


def check_identity(review, compiler, consolidated, roster_audit, review_sha, compiler_sha):
    report.need(review['schema'] == 'ordinary-reviewed-block-attribution-v1'
                and compiler['schema'] == 'provisional-compiler-roster-v1'
                and review['status'] == 'NOT_EVALUATED'
                and review['full_ordinary_only_denominator'] is None, 'invalid_review_schema')
    report.need(review['subject'] == compiler['subject'] == consolidated['z2_subject']
                == roster_audit['older_census_subject'], 'older_subject_mismatch')
    report.need(review['compiler_manifest_sha256'] == consolidated['z2_manifest_sha256'] == compiler_sha
                and consolidated['z2_review_sha256'] == review_sha, 'input_digest_mismatch')
    report.need(consolidated['node_subject'] == roster_audit['subject']
                and consolidated['common_subject'] == roster_audit['common_subject'] == report.PIN
                and review['common_effective_module_lock_verified'] is True
                and compiler['common_effective_commit'] == report.PIN, 'current_subject_or_pin_mismatch')


def receipt_blocks(rows, pkg):
    """Retain coordinate/width identity, not hit counts as new reviewed credit."""
    result = {}
    for row in rows:
        f, a, b, c, d, width = row['id']
        hits = row['count']
        report.need(report.package(f) == pkg and type(width) is int and width > 0
                    and type(hits) is int and hits >= 0, 'malformed_observation')
        key = report.coordinate(f, (a, b), (c, d))
        report.need(key not in result, 'duplicate_observation')
        result[key] = width
    return result


def observation_inventory(consolidated, mode, compiler_rows):
    """Each proposed selection stays a separate receipt, even if coordinates overlap."""
    receipts = []
    for name, selection in consolidated['selections'].items():
        pkg = selection['package']
        mode_row = selection['modes'][mode]
        expected_subject = (consolidated['common_subject'] if pkg == report.COMMON or pkg.startswith(report.COMMON + '/')
                            else consolidated['node_subject'])
        report.need(mode_row['mode'] == mode and selection['classification'] in ('direct', 'shared')
                    and selection['subject'] == expected_subject, 'invalid_selection_mode_class_or_subject')
        rows = [block for fn in mode_row['functions'] for block in fn['blocks']]
        receipts.append((name, pkg, selection['classification'], receipt_blocks(rows, pkg)))
    for name, retained in consolidated['retained_prior'].items():
        pkg = retained['package']
        receipts.append(('retained:' + name, pkg, 'direct', receipt_blocks(retained['modes'][mode]['blocks'], pkg)))
    for _, pkg, _, blocks in receipts:
        report.need(pkg in compiler_rows and blocks, 'observation_outside_census')
        old = attribution.metadata_blocks(compiler_rows[pkg], pkg)
        report.need(old is not None and all(old.get(k) == w for k, w in blocks.items()), 'observation_shape_mismatch')
    return receipts


def reconcile(review, compiler, consolidated, roster_audit, source_digest):
    """Bind reviewed function source bytes; do not transfer historical coverage or adopt new blocks."""
    audits = {r['package']: r for r in roster_audit['rows']}
    report.need(len(audits) == len(roster_audit['rows']), 'duplicate_audit_package')
    result = {'schema': 'ordinary-reviewed-consolidation-diagnostic-v1', 'status': 'NOT_EVALUATED',
              'reviewed_subject': review['subject'], 'node_subject': consolidated['node_subject'],
              'common_subject': consolidated['common_subject'], 'full_ordinary_only_denominator': None,
              'aggregate_coverage': None, 'modes': {}}
    for mode in MODES:
        reviewed_rows = review['modes'][mode]['packages']
        compiler_rows = compiler['mode'][mode]
        roster = {row['package'] for row in reviewed_rows}
        report.need(len(roster) == len(reviewed_rows) and roster == set(audits) == set(compiler_rows),
                    'roster_mismatch')
        proposed = observation_inventory(consolidated, mode, compiler_rows)
        functions, known = [], {}
        for row in reviewed_rows:
            pkg = row['package']
            blocks = attribution.metadata_blocks(compiler_rows[pkg], pkg)
            for fn in row['functions']:
                if fn['status'] != 'reviewed_source_bound':
                    continue
                template = {**fn, 'blocks': fn['reviewed_blocks']}
                status, expected = attribution.match_function(template, compiler_rows[pkg], blocks)
                report.need(status == 'reviewed_source_bound' and not expected.keys() & known.keys(), 'review_block_mismatch')
                report.need(fn['profile_file'] == (report.COMMON if pkg == report.COMMON or pkg.startswith(report.COMMON + '/')
                                                else report.NODE) + '/' + fn['source'], 'review_path_mismatch')
                matched = source_digest(pkg, fn['source']) == fn['source_sha256']
                known.update(expected)
                overlap = [name for name, _, _, obs in proposed if expected.keys() & obs.keys()]
                functions.append({'package': pkg, 'function': fn['name'], 'source': fn['source'],
                                  'prior_reviewed_blocks': len(expected), 'prior_reviewed_statements': sum(expected.values()),
                                  'current_source_matches': matched, 'prior_selector_provenance': row['nominal_selector_provenance'],
                                  'current_compiler_remeasured': False, 'overlapping_receipts': overlap,
                                  'current_coverage': None})
        excluded = []
        for name, pkg, classification, obs in proposed:
            overlap = set(obs) & set(known)
            report.need(all(obs[k] == known[k] for k in overlap), 'reviewed_observation_width_mismatch')
            excluded.append({'receipt': name, 'package': pkg, 'receipt_classification': classification,
                             'reviewed_overlap_blocks': len(overlap), 'coverage_adopted': False,
                             'reason': 'overlap_requires_current_review_and_eligible_producer' if overlap else 'outside_reviewed_manifest'})
        report.need(len(known) == review['modes'][mode]['reviewed_source_bound_blocks']
                    and sum(known.values()) == review['modes'][mode]['reviewed_source_bound_statements'], 'review_totals_mismatch')
        result['modes'][mode] = {'reviewed_functions': functions, 'receipt_dispositions': excluded,
                                 'coverage': None, 'source_matched_functions': sum(f['current_source_matches'] for f in functions)}
    return result


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def source_reader(root, subject, tree):
    report.need(git(root, 'rev-parse', 'HEAD').decode().strip() == subject
                and git(root, 'rev-parse', 'HEAD^{tree}').decode().strip() == tree
                and not git(root, 'status', '--porcelain', '--untracked-files=all'), 'source_checkout_mismatch')
    def digest(source):
        path = Path(source)
        report.need(not path.is_absolute() and '..' not in path.parts and ':' not in source, 'invalid_source_path')
        return report.sha(git(root, 'show', subject + ':' + source))
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('review', 'compiler', 'consolidated', 'roster-audit', 'node-root', 'common-root', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    review, review_sha = loaded(args.review)
    compiler, compiler_sha = loaded(args.compiler)
    consolidated, consolidated_sha = loaded(args.consolidated)
    audit, audit_sha = loaded(args.roster_audit)
    check_identity(review, compiler, consolidated, audit, review_sha, compiler_sha)
    node = source_reader(args.node_root, consolidated['node_subject'], consolidated['node_tree'])
    common = source_reader(args.common_root, consolidated['common_subject'], consolidated['common_tree'])
    report.need(node('go.mod') == compiler['go_mod_sha256'] and node('go.sum') == compiler['go_sum_sha256'],
                'current_node_module_lock_mismatch')
    result = reconcile(review, compiler, consolidated, audit,
                       lambda pkg, source: (common if pkg == report.COMMON or pkg.startswith(report.COMMON + '/') else node)(source))
    result['inputs'] = {'review_sha256': review_sha, 'compiler_sha256': compiler_sha,
                        'consolidated_sha256': consolidated_sha, 'roster_audit_sha256': audit_sha}
    with args.output.open('x') as output:
        output.write(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
