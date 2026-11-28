"""Independent compiler census of the provisional roster; never a qualification gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import report
import attribution

HERE = Path(__file__).resolve().parent
MODES = ('normal', 'race')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def run(root, *args):
    env = dict(os.environ, GOPROXY='off', GONOPROXY='none', GOSUMDB='off', GOVCS='*:off',
               GOTOOLCHAIN='local', GOENV='off', GOWORK='off', GOTELEMETRY='off',
               GOFLAGS='-mod=readonly -buildvcs=false', CGO_ENABLED='1', GOOS='linux', GOARCH='amd64')
    return subprocess.run(args, cwd=root, env=env, check=True, capture_output=True, timeout=120).stdout


def objects(raw):
    decoder = json.JSONDecoder()
    rest = raw.decode().strip()
    while rest:
        value, finish = decoder.raw_decode(rest)
        yield value
        rest = rest[finish:].lstrip()


def git_blobs(root):
    result = {}
    for line in run(root, 'git', 'ls-tree', '-rz', 'HEAD').split(b'\0'):
        if line:
            meta, name = line.split(b'\t', 1)
            mode, typ, digest = meta.decode().split()
            if typ == 'blob' and mode in ('100644', '100755'):
                result[name.decode()] = digest
    return result


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def sources(entry, pkg, base, tracked=None):
    module = entry['Module']
    prefix = report.NODE if pkg == report.NODE or pkg.startswith(report.NODE + '/') else report.COMMON
    require(entry['ImportPath'] == pkg and module['Path'] == prefix, 'package_identity_mismatch')
    require(not entry.get('CgoFiles') and not entry.get('SwigFiles') and not entry.get('SwigCXXFiles'),
            'generated_cgo_source_not_supported')
    directory = base / pkg.removeprefix(prefix).lstrip('/')
    require(Path(entry['Dir']).resolve() == directory.resolve(), 'package_directory_mismatch')
    files = entry['GoFiles']
    require(isinstance(files, list) and len(files) == len(set(files)) and bool(files), 'invalid_file_roster')
    bound = {}
    for name in sorted(files):
        require(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*\.go', name) and not name.endswith('_test.go'), 'invalid_source_name')
        path = directory / name
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(base.resolve()), 'invalid_source_file')
        raw = path.read_bytes()
        if tracked is not None:
            require(tracked.get(path.relative_to(base).as_posix()) == blob(raw), 'node_source_not_in_subject')
        bound[pkg + '/' + name] = report.sha(raw)
    return directory, bound


def independent_blocks(raw, files):
    # Metadata-only text format has zero counters; these counters are never observations.
    rows = report.parse_profile(raw)
    for key, (_, hit) in rows.items():
        require(key[0] in files and not hit, 'invalid_compiler_metadata')
    return {k: n for k, (n, _) in rows.items()}


def compiler_census(root, pkg, entry, base, tracked, work):
    directory, bound = sources(entry, pkg, base, tracked)
    files = [directory / f.rsplit('/', 1)[-1] for f in bound]
    work.mkdir()
    meta = work / 'meta'
    meta.mkdir()
    cfg = work / 'pkgcfg.json'
    cfg.write_text(json.dumps({'OutConfig': str(work / 'fixup.json'), 'PkgPath': pkg,
                               'PkgName': entry['Name'], 'Granularity': 'perblock',
                               'ModulePath': entry['Module']['Path'], 'Local': False,
                               'EmitMetaFile': str(meta / ('covmeta.' + report.sha(pkg.encode())))}))
    output_list = work / 'files.txt'
    output_list.write_text(''.join(str(work / f'{i}.go') + '\n' for i in range(len(files) + 1)))
    run(root, 'go', 'tool', 'cover', '-pkgcfg', str(cfg), '-mode=atomic',
        '-var=goCover_roster_', '-outfilelist', str(output_list), *map(str, files))
    census = work / 'census.cover'
    # A package without instrumentable functions may have no metadata; never guess a zero denominator.
    require(any(meta.iterdir()), 'compiler_metadata_absent')
    run(root, 'go', 'tool', 'covdata', 'textfmt', '-i=' + str(meta), '-o=' + str(census))
    raw = census.read_bytes()
    blocks = independent_blocks(raw, bound)
    require(sources(entry, pkg, base, tracked)[1] == bound, 'source_changed_during_census')
    return {'sources': bound, 'compiler_profile_sha256': report.sha(raw),
            'blocks': [[f, *a, *b, n] for (f, a, b), n in sorted(blocks.items())]}, blocks


def package_measure(blocks, profile, pkg):
    if blocks is None:
        return {'status': 'census_unavailable', 'observation_status': 'census_unavailable',
                'compiler_blocks': None, 'observed_blocks': None, 'missing_blocks': None,
                **report.tally({}, [])}
    selected = {k: v for k, v in profile.items() if report.package(k[0]) == pkg}
    inventory = {'compiler_blocks': len(blocks), 'observed_blocks': None, 'missing_blocks': len(blocks)}
    if any(k not in blocks or blocks[k] != v[0] for k, v in selected.items()):
        return {'status': 'profile_census_mismatch', 'observation_status': 'invalid',
                **inventory, **report.tally(blocks, [])}
    value = report.tally(blocks, [selected])
    status = 'complete' if value['complete_subset_statements'] is not None else 'incomplete'
    # Metadata may have zero-width blocks: census and counter presence are independent
    # of the available positive statement denominator.
    observed = len(selected)
    observation_status = ('not_observed' if not observed else
                          'complete' if observed == len(blocks) else 'partial')
    return {'status': status, 'observation_status': observation_status,
            'compiler_blocks': len(blocks), 'observed_blocks': observed if observed else None,
            'missing_blocks': len(blocks) - observed, **value}


def aggregate(rows):
    available = [r for r in rows if r['compiler_blocks'] is not None]
    observed = [r['observed_statements'] for r in rows if r['observed_statements'] is not None]
    measured = [r for r in rows if r['status'] == 'complete']
    total = sum(r['expected_statements'] or 0 for r in available)
    hit = sum(r['covered'] for r in observed)
    seen = sum(r['total'] for r in observed)
    return {'packages_requested': len(rows), 'packages_with_census': len(available),
            'packages_complete': len(measured),
            'packages_census_unavailable': len(rows) - len(available),
            'packages_observation_status': {s: sum(r['observation_status'] == s for r in rows)
                                            for s in ('not_observed', 'partial', 'complete', 'invalid', 'census_unavailable')},
            'known_compiler_blocks': sum(r['compiler_blocks'] for r in available) if available else None,
            'known_missing_blocks': sum(r['missing_blocks'] for r in available) if available else None,
            'known_expected_statements': total if available else None,
            'observed_statements': {'covered': hit, 'total': seen} if observed else None,
            'complete_statements': {'covered': hit, 'total': total} if rows and len(rows) == len(measured) else None}


def error_reason(exc):
    # Only our own short protocol codes are portable; never publish subprocess paths or errors.
    value = str(exc)
    if type(exc) is ValueError and re.fullmatch(r'[a-z][a-z0-9_]*', value):
        return value
    return 'source_or_tool_input_unavailable'


def common_root(root, work):
    spec = importlib.util.spec_from_file_location('common_receipt', HERE.parent / 'common-direct/diagnostic.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.verify_module(root, work)


def inputs(root, subject, roster, normal, race_input, race_report, common):
    d = root / '.github/coverage/ordinary'
    nt, ct = (d / 'node-direct-r25.json').read_bytes(), (d / 'common-direct/census.json').read_bytes()
    sel = (d / 'node-direct-race/selectors-r28.json').read_bytes()
    nf, cf = json.loads(nt)['functions'], json.loads(ct)['functions']
    profiles, receipts = {}, {}
    for mode in MODES:
        load_node = (lambda: report.normal_node(normal, nf, roster['node'])) if mode == 'normal' else (
            lambda: report.race_node(race_input, race_report, subject, nt, sel, nf, roster['node']))
        available = normal is not None if mode == 'normal' else race_input is not None and race_report is not None
        def source_bound_node():
            report.verify_node_source(root, nf)
            return load_node()
        profiles[mode, 'node'], receipts[mode + '_node'] = report.optional(source_bound_node, available)
        profiles[mode, 'common'], receipts[mode + '_common'] = report.optional(
            lambda: report.common_mode(common, mode, root, ct, cf, roster['common']), common is not None)
    return profiles, receipts


def produce(root, subject, roster, output, paths):
    require(run(root, 'git', 'rev-parse', 'HEAD').decode().strip() == subject, 'checkout_subject_mismatch')
    require(run(root, 'go', 'version').decode().strip() == 'go version go1.26.2 linux/amd64', 'toolchain_mismatch')
    required = roster['node'] + roster['common']
    require(len(required) == 39 and len(set(required)) == 39, 'roster_mismatch')
    output.mkdir(exist_ok=False)
    manifest = {'schema': 'provisional-compiler-roster-v1', 'subject': subject, 'mode': {},
                'toolchain': 'go1.26.2 linux/amd64', 'cgo_enabled': True, 'build_tags': {'normal': [], 'race': ['race']},
                'go_mod_sha256': report.sha((root / 'go.mod').read_bytes()), 'go_sum_sha256': report.sha((root / 'go.sum').read_bytes()),
                'common_effective_commit': report.PIN, 'common_archive_sum': report.SUM, 'common_go_mod_sum': report.MOD_SUM,
                'common_module_verified': False, 'common_module_reason': None}
    profiles, receipts = inputs(root, subject, roster, *paths)
    metrics = {'schema': 'provisional-compiler-roster-result-v1', 'subject': subject, 'inputs': receipts,
               'scope': 'whole selected production package metadata, mixed; not ordinary-only attribution',
               'full_standard_token': None, 'status': 'NOT_EVALUATED', 'mode': {}, 'aggregate': {}}
    tracked = git_blobs(root)
    for lock in ('go.mod', 'go.sum'):
        require(tracked.get(lock) == blob((root / lock).read_bytes()), 'node_lock_not_in_subject')
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        common_dir = None
        try:
            verify_dir = scratch / 'verify'
            verify_dir.mkdir()
            common_dir = common_root(root, verify_dir)
            manifest['common_module_verified'] = True
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            manifest['common_module_reason'] = error_reason(exc)
        for mode in MODES:
            manifest['mode'][mode], metrics['mode'][mode] = {}, {}
            for module, base in (('node', root), ('common', common_dir)):
                for number, pkg in enumerate(roster[module]):
                    blocks = None
                    row = {'status': 'unavailable', 'reason': 'common_module_unverified' if base is None else None}
                    if base is not None:
                        try:
                            args = ['go', 'list', '-json'] + (['-race'] if mode == 'race' else []) + [pkg]
                            entry, = objects(run(root, *args))
                            detail, blocks = compiler_census(root, pkg, entry, base, tracked if module == 'node' else None,
                                                             scratch / f'{mode}-{module}-{number}')
                            row = {'status': 'metadata_present', **detail}
                        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                            row['reason'] = error_reason(exc)
                    manifest['mode'][mode][pkg] = row
                    metrics['mode'][mode][pkg] = package_measure(blocks, profiles[mode, module], pkg)
            metrics['aggregate'][mode] = {module: aggregate([metrics['mode'][mode][pkg] for pkg in roster[module]])
                                          for module in ('node', 'common')}
            metrics['aggregate'][mode]['roster'] = aggregate(list(metrics['mode'][mode].values()))
    data = (json.dumps(manifest, separators=(',', ':')) + '\n').encode()
    (output / 'compiler-manifest.json').write_bytes(data)
    metrics['compiler_manifest_sha256'] = report.sha(data)
    (output / 'compiler-report.json').write_text(json.dumps(metrics, indent=2) + '\n')
    reviewed = attribution.build(root, manifest, metrics['compiler_manifest_sha256'], roster)
    (output / 'reviewed-attribution.json').write_text(json.dumps(reviewed, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--subject', required=True)
    parser.add_argument('--output', required=True, type=Path)
    for arg in ('normal-dir', 'race-input', 'race-report', 'common-dir'):
        parser.add_argument('--' + arg, default='')
    a = parser.parse_args()
    require(re.fullmatch(r'[a-f0-9]{40}', a.subject), 'invalid_subject')
    paths = tuple(Path(x) if x else None for x in (a.normal_dir, a.race_input, a.race_report, a.common_dir))
    produce(a.checkout.resolve(), a.subject, json.loads((HERE / 'roster.json').read_bytes()), a.output, paths)


if __name__ == '__main__':
    main()
