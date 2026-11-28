"""Reconcile only already-reviewed ordinary-only blocks; no test execution or gate."""
import json
from pathlib import Path
import re

import report

NODE_CENSUS = '1e8e80969035106a7f7f08820b34b8472eab3864ac089dd5b6729c7ecda5a7ae'
COMMON_CENSUS = '99c87ebbc6421c68c366fded3325a32b4a9d93a8b2d151eda1420985e3e5e77f'
RACE_SELECTORS = 'c91ecacc58d955517f538f9f27a58ffc39fd91353c1b06fcc07a6d8eb30d0384'
RACE_REVIEW = '8bd94f4dd795da74a2522c6d5b006bca1310fa352c9d1b1c818b678f449b7554'
REPRESENTATION_PROPOSALS = '60decb32b41ce7fa9583880251a2d60d2abf95f68af48c437e6e8c498bfd6851'
MODES = ('normal', 'race')
COMMON_ROOTS = ['TestComputeTokenIdentifier', 'TestExtractTokenAndNonce']


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def locked_json(root, name, digest):
    raw = (root / name).read_bytes()
    require(report.sha(raw) == digest, 'reviewed_manifest_digest_mismatch')
    return json.loads(raw)


def selector_lock(root, selectors):
    """Check exact reviewed nominal selector file bytes; no new test discovery."""
    try:
        require(selectors['review_sha256'] == RACE_REVIEW and selectors['census_sha256'] == NODE_CENSUS,
                'selector_review_mismatch')
        files = selectors['files']
        require(bool(files), 'empty_selector_lock')
        for name, digest in files.items():
            path = Path(name)
            require(not path.is_absolute() and '..' not in path.parts, 'invalid_selector_path')
            source = root / path
            require(source.is_file() and not source.is_symlink() and source.resolve().is_relative_to(root.resolve())
                    and report.sha(source.read_bytes()) == digest, 'selector_source_mismatch')
        packages = selectors['packages']
        roots = {report.NODE + '/' + p['package']: p['roots'] for p in packages}
        require(len(roots) == len(packages) and all(v and len(set(v)) == len(v) and
                    all(re.fullmatch(r'Test[A-Za-z0-9_]+', n) for n in v) for v in roots.values()), 'invalid_selector_roster')
        return roots, True
    except (OSError, ValueError, KeyError, TypeError):
        return {}, False


def metadata_blocks(row, pkg):
    if row['status'] != 'metadata_present':
        return None
    result = {}
    for file, a, b, c, d, width in row['blocks']:
        require(report.package(file) == pkg and file in row['sources'] and type(width) is int and width >= 0,
                'invalid_compiler_block')
        key = report.coordinate(file, (a, b), (c, d), allow_empty=width == 0)
        require(key not in result, 'duplicate_compiler_block')
        result[key] = width
    return result


def match_function(fn, row, blocks):
    if blocks is None:
        return 'compiler_census_unavailable', {}
    file, span = fn['profile_file'], fn['span']
    if row['sources'].get(file) != fn['source_sha256']:
        return 'reviewed_source_mismatch', {}
    start, end = tuple(span[:2]), tuple(span[2:])
    expected = {(file, tuple(b['start']), tuple(b['end'])): b['statements'] for b in fn['blocks']}
    # Verify the whole reviewed function's positive compiler-block set, not just its intersection.
    actual = {key: width for key, width in blocks.items() if key[0] == file and width > 0
              and key[1] < end and start < key[2]}
    if expected != actual:
        return 'reviewed_compiler_blocks_mismatch', {}
    return 'reviewed_source_bound', expected


def scope_status(module, mode, pkg, race_roots, race_verified, common_verified):
    if module == 'common':
        return ('reviewed_nominal_selector' if common_verified else 'common_source_lock_unverified')
    if mode == 'normal':
        return 'reviewed_direct_blocks_primary_mixed_profile'
    if not race_verified:
        return 'race_selector_lock_unverified'
    return 'reviewed_nominal_selector' if pkg in race_roots else 'no_admitted_nominal_selector'


def reconcile(compiler, roster, node, common, race_roots, race_verified):
    """Only the reviewed function manifests grant attribution; all else remains unreviewed."""
    packages = roster['node'] + roster['common']
    require(len(set(packages)) == len(packages), 'duplicate_roster_package')
    require(compiler['schema'] == 'provisional-compiler-roster-v1' and set(compiler['mode']) == set(MODES),
            'invalid_compiler_manifest')
    # Reuse the existing static review's strict coordinates, spans, width and duplicate checks.
    report.census(node, roster['node'])
    report.census(common, roster['common'])
    templates = node + common
    expected_total = sum(b['statements'] for fn in templates for b in fn['blocks'])
    common_verified = (compiler.get('common_module_verified') is True and compiler.get('common_effective_commit') == report.PIN
                       and compiler.get('common_archive_sum') == report.SUM and compiler.get('common_go_mod_sum') == report.MOD_SUM)
    result = {'schema': 'ordinary-reviewed-block-attribution-v1', 'subject': compiler['subject'], 'status': 'NOT_EVALUATED',
              'scope': 'existing reviewed direct ordinary-only subset; unresolved compiler blocks are not ordinary attribution',
              'reviewed_template_statements': expected_total, 'full_ordinary_only_denominator': None,
              'node_race_selector_lock_verified': race_verified, 'common_effective_module_lock_verified': common_verified,
              'modes': {}}
    for mode in MODES:
        ml = compiler['mode'][mode]
        require(set(ml) == set(packages), 'compiler_roster_mismatch')
        rows = []
        for pkg in packages:
            module = 'node' if pkg in roster['node'] else 'common'
            row = ml[pkg]
            blocks = metadata_blocks(row, pkg)
            functions = []
            reviewed_keys = {}
            producer = scope_status(module, mode, pkg, race_roots, race_verified, common_verified)
            nominal_roots = (COMMON_ROOTS if common_verified else []) if module == 'common' else (race_roots.get(pkg, []) if race_verified else [])
            for fn in templates:
                if report.package(fn['profile_file']) != pkg:
                    continue
                status, verified = match_function(fn, row, blocks)
                if module == 'common' and not common_verified:
                    status, verified = 'common_source_lock_unverified', {}
                require(not reviewed_keys.keys() & verified.keys(), 'duplicate_reviewed_block')
                reviewed_keys.update(verified)
                functions.append({'name': fn['name'], 'source': fn['source'], 'profile_file': fn['profile_file'],
                                  'source_sha256': fn['source_sha256'], 'span': fn['span'], 'status': status,
                                  'reviewed_blocks': fn['blocks'] if verified else None,
                                  'review_template_statements': sum(b['statements'] for b in fn['blocks'])})
            reviewed = sum(reviewed_keys.values())
            expected = sum(fn['review_template_statements'] for fn in functions)
            compiler_statements = sum(blocks.values()) if blocks is not None else None
            positive_blocks = sum(width > 0 for width in blocks.values()) if blocks is not None else None
            if blocks is None:
                status = 'compiler_census_unavailable'
            elif not functions:
                status = 'unreviewed'
            elif reviewed == expected:
                status = 'reviewed_subset_only'
            else:
                status = 'reviewed_subset_partial_or_unbound'
            rows.append({'package': pkg, 'status': status, 'producer_scope': producer if functions else 'unreviewed',
                         'nominal_selector_provenance': ({'roots': nominal_roots, 'producer_modes': list(MODES) if module == 'common' else ['race']}
                                                        if functions and nominal_roots else None),
                         'compiler_statements_mixed': compiler_statements,
                         'compiler_blocks_mixed': len(blocks) if blocks is not None else None,
                         'compiler_zero_statement_blocks': len(blocks) - positive_blocks if blocks is not None else None,
                         'unresolved_mixed_positive_blocks': positive_blocks - len(reviewed_keys) if blocks is not None else None,
                         'review_template_statements': expected or None,
                         'reviewed_source_bound_statements': reviewed or None,
                         'reviewed_source_bound_blocks': len(reviewed_keys) or None,
                         'unresolved_mixed_statements': compiler_statements - reviewed if blocks is not None else None,
                         'functions': functions})
        verified_rows = [r for r in rows if r['reviewed_source_bound_statements'] is not None]
        nominal = [r for r in verified_rows if r['producer_scope'] == 'reviewed_nominal_selector']
        nominal_provenance = [r for r in verified_rows if r['nominal_selector_provenance'] is not None]
        producer_rows = [r for r in verified_rows if r['producer_scope'] in
                         ('reviewed_nominal_selector', 'reviewed_direct_blocks_primary_mixed_profile')]
        sumv = lambda selected: sum(r['reviewed_source_bound_statements'] for r in selected)
        census_rows = [r for r in rows if r['compiler_blocks_mixed'] is not None]
        known = lambda key: sum(r[key] for r in census_rows) if census_rows else None
        result['modes'][mode] = {'packages': rows, 'packages_requested': len(rows), 'packages_with_reviewed_subset': len(verified_rows),
                                 'packages_with_compiler_census': len(census_rows),
                                 'packages_without_compiler_census': len(rows) - len(census_rows),
                                 'known_compiler_blocks_mixed': known('compiler_blocks_mixed'),
                                 'known_compiler_zero_statement_blocks': known('compiler_zero_statement_blocks'),
                                 'known_compiler_statements_mixed': known('compiler_statements_mixed'),
                                 'known_unresolved_mixed_positive_blocks': known('unresolved_mixed_positive_blocks'),
                                 'known_unresolved_mixed_statements': known('unresolved_mixed_statements'),
                                 'packages_without_reviewed_subset': len(rows) - len(verified_rows),
                                 'reviewed_source_bound_functions': sum(fn['status'] == 'reviewed_source_bound' for r in rows for fn in r['functions']),
                                 'reviewed_source_bound_blocks': sum(r['reviewed_source_bound_blocks'] for r in verified_rows),
                                 'reviewed_source_bound_statements': sumv(verified_rows),
                                 'existing_producer_scope_statements': sumv(producer_rows),
                                 'reviewed_nominal_provenance_statements': sumv(nominal_provenance),
                                 'explicit_nominal_selector_scope_statements': sumv(nominal)}
    return result


def representation_proposals(compiler, roster, reviewed, proposals, common_verified):
    """Source-bind detached DTO proposals without admitting attribution or counters."""
    packages = roster['node'] + roster['common']
    require(proposals['schema'] == 'detached-token-representation-proposals-v1', 'invalid_proposal_schema')
    functions = proposals['functions']
    # Check proposed blocks against each other and all prior reviewed templates, including unbound rows.
    report.census(reviewed + functions, packages)
    report.census(functions, packages)
    result = {'status': 'PROPOSED_NOT_ADMITTED', 'coverage': None, 'ordinary_only_denominator': None,
              'modes': {}}
    for mode in MODES:
        rows = []
        for fn in functions:
            pkg = report.package(fn['profile_file'])
            row = compiler['mode'][mode][pkg]
            status, bound = match_function(fn, row, metadata_blocks(row, pkg))
            if pkg in roster['common'] and not common_verified:
                status, bound = 'common_source_lock_unverified', {}
            rows.append({**fn, 'status': 'proposed_source_bound' if bound else status,
                         'source_bound_blocks': len(bound) if bound else None,
                         'source_bound_statements': sum(bound.values()) if bound else None})
        matched = [r for r in rows if r['source_bound_blocks'] is not None]
        result['modes'][mode] = {
            'functions': rows, 'proposed_functions': len(rows), 'source_bound_functions': len(matched),
            'known_source_bound_blocks': sum(r['source_bound_blocks'] for r in matched) if matched else None,
            'known_source_bound_statements': sum(r['source_bound_statements'] for r in matched) if matched else None,
        }
    return result


def build(root, compiler, compiler_sha, roster):
    directory = root / '.github/coverage/ordinary'
    node = locked_json(directory, 'node-direct-r25.json', NODE_CENSUS)
    common = locked_json(directory, 'common-direct/census.json', COMMON_CENSUS)
    require(common['common_commit'] == report.PIN, 'reviewed_common_pin_mismatch')
    selectors = locked_json(directory, 'node-direct-race/selectors-r28.json', RACE_SELECTORS)
    roots, verified = selector_lock(root, selectors)
    value = reconcile(compiler, roster, node['functions'], common['functions'], roots, verified)
    proposals = locked_json(directory / 'standard-token', 'representation-proposals.json', REPRESENTATION_PROPOSALS)
    value['detached_representation_proposals'] = representation_proposals(
        compiler, roster, node['functions'] + common['functions'], proposals,
        value['common_effective_module_lock_verified'])
    value['detached_representation_proposals']['manifest_sha256'] = REPRESENTATION_PROPOSALS
    value.update(compiler_manifest_sha256=compiler_sha, reviewed_node_template_sha256=NODE_CENSUS,
                 reviewed_common_template_sha256=COMMON_CENSUS, reviewed_race_selector_sha256=RACE_SELECTORS,
                 reviewed_race_selector_review_sha256=RACE_REVIEW,
                 common_nominal_roots=COMMON_ROOTS)
    return value
