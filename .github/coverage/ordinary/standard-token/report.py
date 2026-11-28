"""Current-attempt, read-only standard-token diagnostic; never a coverage gate."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import subprocess

NODE = 'github.com/multiversx/mx-chain-go'
COMMON = 'github.com/multiversx/mx-chain-vm-common-go'
MOD = 'github.com/xorewa/mx-chain-vm-common-go'
PIN = '65fdfdd8ff11f6b98489b60efd35e9c682979dd0'
VERSION = 'v0.0.0-20261121171453-65fdfdd8ff11'
SUM = 'h1:wXchOd4x7UXBYbZtNK7wqOU9RXAjCrNr0rgmOfr014A='
MOD_SUM = 'h1:Lk2ZNxVCThYFbFhjXxy1S8PwqjcEnF7uvTQ0QvA4BbQ='
HERE = Path(__file__).resolve().parent
COVER = re.compile(r'([^\s:]+):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)')


def need(condition, code):
    if not condition:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(directory, name):
    path = directory / name
    need(not directory.is_symlink() and not path.is_symlink() and path.is_file(), 'artifact_absent')
    return path.read_bytes()


def obj(directory, name):
    return json.loads(read(directory, name))


def package(file):
    return file.rsplit('/', 1)[0]


def coordinate(file, start, end, allow_empty=False):
    need(len(start) == len(end) == 2 and all(type(n) is int and n > 0 for n in (*start, *end))
         and (tuple(start) < tuple(end) or (allow_empty and tuple(start) == tuple(end))), 'invalid_coordinate')
    return file, tuple(start), tuple(end)


def parse_profile(raw):
    lines = raw.decode().splitlines()
    need(bool(lines) and lines[0] == 'mode: atomic', 'invalid_profile_mode')
    result = {}
    for line in lines[1:]:
        match = COVER.fullmatch(line)
        need(match is not None, 'invalid_profile_row')
        f, *nums = match.groups()
        a, b, c, d, width, hits = map(int, nums)
        key = coordinate(f, (a, b), (c, d), allow_empty=width == 0)
        old = result.get(key)
        need(old is None or old[0] == width, 'conflicting_profile_width')
        result[key] = (width, hits > 0 or (old is not None and old[1]))
    need(bool(result), 'empty_profile')
    return result


def census(functions, roster):
    blocks, identities = {}, set()
    spans = defaultdict(list)
    for fn in functions:
        file, source = fn['profile_file'], fn['source']
        need(package(file) in roster and file.endswith('/' + source), 'manifest_outside_roster')
        need(re.fullmatch(r'[a-f0-9]{64}', fn['source_sha256']) is not None, 'invalid_source_digest')
        need(not Path(source).is_absolute() and '..' not in Path(source).parts, 'invalid_source_path')
        span = fn['span']
        need(len(span) == 4, 'invalid_function_span')
        _, first, last = coordinate(file, span[:2], span[2:])
        identity = file, tuple(span), fn['name']
        need(identity not in identities and bool(fn['blocks']), 'duplicate_or_empty_function')
        identities.add(identity)
        for b in fn['blocks']:
            key = coordinate(file, b['start'], b['end'])
            width = b['statements']
            need(type(width) is int and width > 0 and first <= key[1] < key[2] <= last, 'invalid_manifest_block')
            need(key not in blocks, 'duplicate_manifest_block')
            blocks[key] = width
            spans[file].append((key[1], key[2]))
    for intervals in spans.values():
        ordered = sorted(intervals)
        need(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), 'overlapping_manifest_blocks')
    need(bool(blocks), 'empty_manifest')
    return blocks


def tally(expected, profiles):
    """Join exact compatible blocks by logical hit; absence is not a zero counter."""
    observed = {}
    for profile in profiles:
        for key, (width, hit) in profile.items():
            if key not in expected:
                continue
            need(width == expected[key], 'manifest_profile_width_mismatch')
            observed[key] = bool(hit or observed.get(key, False))
    total = sum(expected.values())
    seen = sum(expected[k] for k in observed)
    hit = sum(expected[k] for k, yes in observed.items() if yes)
    return {'expected_statements': total or None, 'observed_statements': {'covered': hit, 'total': seen} if seen else None,
            'missing_statements': total - seen if total else None,
            'complete_subset_statements': {'covered': hit, 'total': total} if total and seen == total else None}


def counts(profile, pkg):
    values = [v for k, v in profile.items() if package(k[0]) == pkg]
    return {'covered': sum(n for n, h in values if h), 'total': sum(n for n, _ in values)} if values else None


def validated_report(directory, report_name, manifest_name, functions, raw, roster):
    manifest_raw = read(directory, manifest_name)
    manifest = json.loads(manifest_raw)
    profile_sha = sha(raw)
    need(manifest == {'profile_sha256': profile_sha, 'functions': functions}, 'bound_manifest_mismatch')
    report = obj(directory, report_name)
    need(report.get('profile_status') == 'present' and report.get('profile_mode') == 'atomic'
         and report.get('profile_sha256') == profile_sha and report.get('manifest_sha256') == sha(manifest_raw),
         'function_report_binding_mismatch')
    profile = parse_profile(raw)
    expected = census(functions, roster)
    check = tally(expected, [profile])
    observed = check['observed_statements'] or {'covered': 0, 'total': 0}
    need(report.get('expected_statements') == check['expected_statements']
         and report.get('observed_statements') == observed
         and report.get('aggregate_statements') == check['complete_subset_statements'], 'function_report_count_mismatch')
    return profile, profile_sha


def verify_node_source(root, functions):
    for fn in functions:
        source = fn['source']
        need(not Path(source).is_absolute() and '..' not in Path(source).parts, 'invalid_source_path')
        path = root / source
        need(path.resolve().is_relative_to(root.resolve()) and path.is_file()
             and sha(path.read_bytes()) == fn['source_sha256'], 'node_source_mismatch')


def normal_node(directory, functions, roster):
    receipt = obj(directory, 'input.json')
    need(receipt.get('status') == 'bound' and receipt.get('profile_before') == 'absent'
         and receipt.get('primary_outcome') == 'success', 'normal_input_unbound')
    raw = read(directory, 'coverage-input.cover')
    need(receipt.get('profile_sha256') == sha(raw), 'normal_profile_digest_mismatch')
    return validated_report(directory, 'node-direct-r25.json', 'node-direct-r25-bound-manifest.json', functions, raw, roster)


def race_node(input_dir, report_dir, subject, template, selectors, functions, roster):
    receipt = obj(report_dir, 'provenance.json')
    raw = read(input_dir, 'coverage.out')
    need(receipt == {'run_mode': 'race', 'subject': subject, 'selector_review_sha256':
                      '8bd94f4dd795da74a2522c6d5b006bca1310fa352c9d1b1c818b678f449b7554',
                      'selector_manifest_sha256': sha(selectors), 'census_sha256': sha(template),
                      'profile_sha256': sha(raw), 'test_exit': 0, 'status': 'caller_receipt_matched'},
         'race_receipt_mismatch')
    need(type(receipt['test_exit']) is int, 'invalid_test_exit')
    return validated_report(report_dir, 'report.json', 'bound-manifest.json', functions, raw, roster)


def common_mode(directory, mode, root, template, functions, roster):
    summary = obj(directory, 'summary.json')
    lock = (root / 'go.mod').read_text().splitlines()
    sums = (root / 'go.sum').read_text().splitlines()
    need(f'replace {COMMON} => {MOD} {VERSION}' in lock and f'{MOD} {VERSION} {SUM}' in sums
         and f'{MOD} {VERSION}/go.mod {MOD_SUM}' in sums, 'common_lock_mismatch')
    need(all(summary.get(k) == v for k, v in {'common_commit': PIN, 'module': MOD, 'version': VERSION,
         'archive_sum': SUM, 'go_mod_sum': MOD_SUM, 'census_sha256': sha(template),
         'package': COMMON + '/parsers/dataField', 'selected_roots': ['TestComputeTokenIdentifier', 'TestExtractTokenAndNonce']}.items()),
         'common_receipt_mismatch')
    claim = summary.get(mode, {})
    raw = read(directory, mode + '.cover')
    need(claim.get('status') == 'measured' and type(claim.get('test_exit')) is int and claim['test_exit'] == 0
         and claim.get('profile_sha256') == sha(raw), 'common_mode_unbound')
    profile, digest = validated_report(directory, mode + '.report.json', mode + '.manifest.json', functions, raw, roster)
    check = tally(census(functions, roster), [profile])
    need(claim.get('statements') == check['complete_subset_statements'] and summary.get('expected_statements') == check['expected_statements'],
         'common_summary_count_mismatch')
    return profile, digest


def optional(load, supplied):
    if not supplied:
        return {}, {'status': 'not_supplied', 'profile_sha256': None}
    try:
        result, digest = load()
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}, {'status': 'unavailable_or_invalid', 'profile_sha256': None}
    return result, {'status': 'bound_partial_diagnostic', 'profile_sha256': digest}


def build_report(root, subject, roster, node_template, common_template, selectors, normal, race_input, race_report, common):
    need(roster.get('schema') == 'standard-token-provisional-roster-v1', 'invalid_roster_schema')
    node, common_roster = roster['node'], roster['common']
    all_packages = node + common_roster
    need(len(node) == len(set(node)) and len(common_roster) == len(set(common_roster))
         and all(p == NODE or p.startswith(NODE + '/') for p in node)
         and all(p == COMMON or p.startswith(COMMON + '/') for p in common_roster), 'invalid_roster')
    nf = json.loads(node_template)['functions']
    cf = json.loads(common_template)['functions']
    expected = census(nf + cf, all_packages)
    verify_node_source(root, nf)
    profiles, inputs = {}, {}
    for mode in ('normal', 'race'):
        if mode == 'normal':
            loader, supplied = lambda: normal_node(normal, nf, node), normal is not None
        else:
            loader, supplied = lambda: race_node(race_input, race_report, subject, node_template, selectors, nf, node), race_input is not None and race_report is not None
        profiles[mode, 'node'], inputs[mode + '_node'] = optional(loader, supplied)
        profiles[mode, 'common'], inputs[mode + '_common'] = optional(lambda: common_mode(common, mode, root, common_template, cf, common_roster), common is not None)
    scoped = {mode: [{k: v for k, v in profiles[mode, 'node'].items() if package(k[0]) in node},
                     {k: v for k, v in profiles[mode, 'common'].items() if package(k[0]) in common_roster}]
              for mode in ('normal', 'race')}

    def stats(blocks, mode):
        return tally(blocks, scoped[mode])
    rows = []
    for pkg in all_packages:
        blocks = {k: v for k, v in expected.items() if package(k[0]) == pkg}
        rows.append({'package': pkg, 'attribution': 'partial_reviewed_subset' if blocks else 'unreviewed',
                     'normal': stats(blocks, 'normal'), 'race': stats(blocks, 'race'),
                     'node_primary_mixed_normal': counts(profiles['normal', 'node'], pkg)})
    return {'schema': 'standard-token-diagnostic-v1', 'subject': subject, 'status': 'NOT_EVALUATED',
            'scope': 'provisional roster; attributed subset only; no threshold or qualification',
            'node_census_sha256': sha(node_template), 'common_census_sha256': sha(common_template),
            'inputs': inputs, 'packages': rows, 'attributed_subset': {m: stats(expected, m) for m in ('normal', 'race')},
            'full_standard_token': {'expected_statements': None, 'covered_statements': None, 'percent': None},
            'full_common_module_profile': 'not_supplied'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--subject', required=True)
    for arg in ('normal-dir', 'race-input', 'race-report', 'common-dir'):
        parser.add_argument('--' + arg, default='')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.checkout.resolve()
    need(re.fullmatch(r'[a-f0-9]{40}', args.subject) is not None and subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip() == args.subject, 'checkout_subject_mismatch')
    d = root / '.github/coverage/ordinary'
    paths = [Path(x) if x else None for x in (args.normal_dir, args.race_input, args.race_report, args.common_dir)]
    result = build_report(root, args.subject, json.loads((HERE / 'roster.json').read_bytes()),
                          (d / 'node-direct-r25.json').read_bytes(), (d / 'common-direct/census.json').read_bytes(),
                          (d / 'node-direct-race/selectors-r28.json').read_bytes(), *paths)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
