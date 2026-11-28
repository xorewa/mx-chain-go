"""Pure synthetic profile and manifest fixtures; no product tests or network."""
import copy
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import report as r


def encoded(value):
    return (json.dumps(value) + '\n').encode()


def store(path, value):
    path.write_bytes(encoded(value))


class ArithmeticTests(unittest.TestCase):
    def setUp(self):
        self.file = r.NODE + '/labels/fixture.go'
        self.fn = {'source': 'labels/fixture.go', 'source_sha256': 'a'*64,
                   'profile_file': self.file, 'name': 'Fixture', 'span': [1,1,9,1],
                   'blocks': [{'start':[2,1], 'end':[3,1], 'statements': 2},
                              {'start':[4,1], 'end':[5,1], 'statements': 3}]}
        self.roster = [r.NODE+'/labels']
        self.expected = r.census([self.fn], self.roster)
        self.a = (self.file, (2,1), (3,1))
        self.b = (self.file, (4,1), (5,1))

    def test_unique_coverage_and_zero_vs_missing(self):
        self.assertEqual(r.tally(self.expected, []), {'expected_statements':5, 'observed_statements':None,
            'missing_statements':5, 'complete_subset_statements':None})
        self.assertEqual(r.tally(self.expected, [{self.a:(2,False)}]), {'expected_statements':5,
            'observed_statements':{'covered':0,'total':2}, 'missing_statements':3, 'complete_subset_statements':None})
        x=r.tally(self.expected,[{self.a:(2,False),self.b:(3,True)}, {self.a:(2,True),self.b:(3,True)}])
        self.assertEqual(x, {'expected_statements':5,'observed_statements':{'covered':5,'total':5},
            'missing_statements':0,'complete_subset_statements':{'covered':5,'total':5}})
        self.assertEqual(r.tally({}, [{}]), {'expected_statements':None,'observed_statements':None,
            'missing_statements':None,'complete_subset_statements':None})
        self.assertEqual(r.counts({self.a:(2,False)}, self.roster[0]),{'covered':0,'total':2})
        self.assertIsNone(r.counts({},self.roster[0]))
        with self.assertRaisesRegex(ValueError,'width_mismatch'):
            r.tally(self.expected,[{self.a:(3,True)}])

    def test_profile_parsing(self):
        raw = f'mode: atomic\n{self.file}:2.1,3.1 2 0\n{self.file}:2.1,3.1 2 9\n'.encode()
        self.assertEqual(r.parse_profile(raw),{self.a:(2,True)})
        empty = f'{self.file}:3.1,3.1 0 0\n'.encode()
        self.assertEqual(r.parse_profile(raw+empty)[(self.file,(3,1),(3,1))],(0,False))
        with self.assertRaisesRegex(ValueError,'invalid_coordinate'):
            r.parse_profile(raw+f'{self.file}:3.1,3.1 1 0\n'.encode())
        for text,reason in [('mode: set\n','invalid_profile_mode'),('mode: atomic\n','empty_profile'),
            ('mode: atomic\ninvalid\n','invalid_profile_row'),
            (f'mode: atomic\n{self.file}:3.1,2.1 2 0\n','invalid_coordinate'),
            (raw.decode()+f'{self.file}:2.1,3.1 4 1\n','conflicting_profile_width')]:
            with self.subTest(reason=reason),self.assertRaisesRegex(ValueError,reason):r.parse_profile(text.encode())

    def test_invalid_census(self):
        cases=[]
        f=copy.deepcopy(self.fn);f['blocks']+=f['blocks'][:1];cases.append((f,'duplicate_manifest_block'))
        f=copy.deepcopy(self.fn);f['blocks'][1]['start']=[2,2];cases.append((f,'overlapping_manifest_blocks'))
        f=copy.deepcopy(self.fn);f['blocks'][0]['statements']=0;cases.append((f,'invalid_manifest_block'))
        f=copy.deepcopy(self.fn);f['source_sha256']='bad';cases.append((f,'invalid_source_digest'))
        f=copy.deepcopy(self.fn);f['span']=[1,1];cases.append((f,'invalid_function_span'))
        f=copy.deepcopy(self.fn);f['blocks']=[];cases.append((f,'duplicate_or_empty_function'))
        f=copy.deepcopy(self.fn);f['profile_file']='example.invalid/fixture.go';cases.append((f,'manifest_outside_roster'))
        for f,reason in cases:
            with self.subTest(reason=reason),self.assertRaisesRegex(ValueError,reason):r.census([f],self.roster)
        with self.assertRaisesRegex(ValueError,'duplicate_or_empty_function'):r.census([self.fn,self.fn],self.roster)
        with self.assertRaisesRegex(ValueError,'empty_manifest'):r.census([],self.roster)


class BoundFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.node_dir=self.root/'normal';self.node_dir.mkdir()
        self.race_dir=self.root/'race';self.race_dir.mkdir();self.race_report=self.root/'race-report';self.race_report.mkdir()
        self.common_dir=self.root/'common';self.common_dir.mkdir()
        self.node_pkg=r.NODE+'/labels';self.common_pkg=r.COMMON+'/parsers/dataField'
        self.node_file=self.node_pkg+'/fixture.go';self.common_file=self.common_pkg+'/fixture.go'
        source=b'fixture source only';(self.root/'labels').mkdir();(self.root/'labels/fixture.go').write_bytes(source)
        self.nf=[self.function(self.node_file,'labels/fixture.go',r.sha(source),2)]
        self.cf=[self.function(self.common_file,'parsers/dataField/fixture.go','c'*64,3)]
        self.roster={'schema':'standard-token-provisional-roster-v1','node':[self.node_pkg,r.NODE+'/unreviewed'], 'common':[self.common_pkg]}
        self.nt=encoded({'functions':self.nf});self.ct=encoded({'functions':self.cf});self.selectors=b'reviewed synthetic selectors'
        self.subject='a'*40
        (self.root/'go.mod').write_text(f'replace {r.COMMON} => {r.MOD} {r.VERSION}\n')
        (self.root/'go.sum').write_text(f'{r.MOD} {r.VERSION} {r.SUM}\n{r.MOD} {r.VERSION}/go.mod {r.MOD_SUM}\n')

    @staticmethod
    def function(file,source,digest,n):
        return {'source':source,'source_sha256':digest,'profile_file':file,'name':'Fixture',
                'span':[1,1,4,1], 'blocks':[{'start':[2,1],'end':[3,1],'statements':n}]}

    def artifacts(self,directory,raw,functions,report_name,manifest_name):
        m={'profile_sha256':r.sha(raw),'functions':functions};store(directory/manifest_name,m)
        expected=r.census(functions,self.roster['node']+self.roster['common']);counts=r.tally(expected,[r.parse_profile(raw)])
        store(directory/report_name,{'profile_status':'present','profile_mode':'atomic','profile_sha256':r.sha(raw),
            'manifest_sha256':r.sha((directory/manifest_name).read_bytes()),'expected_statements':counts['expected_statements'],
            'observed_statements':counts['observed_statements'] or {'covered':0,'total':0},'aggregate_statements':counts['complete_subset_statements']})
        return counts['complete_subset_statements']

    @staticmethod
    def profile(file,n,h):return f'mode: atomic\n{file}:2.1,3.1 {n} {h}\n'.encode()

    def normal(self):
        raw=self.profile(self.node_file,2,0);(self.node_dir/'coverage-input.cover').write_bytes(raw)
        store(self.node_dir/'input.json',{'status':'bound','profile_before':'absent','primary_outcome':'success','profile_sha256':r.sha(raw)})
        self.artifacts(self.node_dir,raw,self.nf,'node-direct-r25.json','node-direct-r25-bound-manifest.json')

    def race(self):
        raw=self.profile(self.node_file,2,1);(self.race_dir/'coverage.out').write_bytes(raw)
        store(self.race_report/'provenance.json',{'run_mode':'race','subject':self.subject,'selector_review_sha256':
            '8bd94f4dd795da74a2522c6d5b006bca1310fa352c9d1b1c818b678f449b7554', 'selector_manifest_sha256':r.sha(self.selectors),
            'census_sha256':r.sha(self.nt),'profile_sha256':r.sha(raw),'test_exit':0,'status':'caller_receipt_matched'})
        self.artifacts(self.race_report,raw,self.nf,'report.json','bound-manifest.json')

    def common(self):
        s={'common_commit':r.PIN,'module':r.MOD,'version':r.VERSION,'archive_sum':r.SUM,'go_mod_sum':r.MOD_SUM,
           'census_sha256':r.sha(self.ct),'package':self.common_pkg,'selected_roots':['TestComputeTokenIdentifier','TestExtractTokenAndNonce'],
           'expected_statements':3}
        for mode,hit in [('normal',1),('race',0)]:
            raw=self.profile(self.common_file,3,hit);(self.common_dir/(mode+'.cover')).write_bytes(raw)
            stat=self.artifacts(self.common_dir,raw,self.cf,mode+'.report.json',mode+'.manifest.json')
            s[mode]={'status':'measured','test_exit':0,'profile_sha256':r.sha(raw),'statements':stat}
        store(self.common_dir/'summary.json',s)

    def build(self,normal=True,race=True,common=True):
        return r.build_report(self.root,self.subject,self.roster,self.nt,self.ct,self.selectors,
            self.node_dir if normal else None,self.race_dir if race else None,self.race_report if race else None,self.common_dir if common else None)

    def test_full_subset_is_not_gate(self):
        self.normal();self.race();self.common();x=self.build()
        self.assertEqual(x['status'],'NOT_EVALUATED');self.assertIsNone(x['full_standard_token']['percent'])
        self.assertEqual(x['attributed_subset']['normal']['complete_subset_statements'],{'covered':3,'total':5})
        self.assertEqual(x['attributed_subset']['race']['complete_subset_statements'],{'covered':2,'total':5})
        self.assertIsNone(x['packages'][1]['normal']['expected_statements']);self.assertEqual(x['packages'][1]['attribution'],'unreviewed')
        self.assertEqual(x['full_common_module_profile'],'not_supplied')
        self.assertTrue(all(v['status']=='bound_partial_diagnostic' for v in x['inputs'].values()))

    def test_absent_and_invalid_inputs_are_independent(self):
        self.normal();self.race();self.common()
        (self.race_report/'provenance.json').write_text('{}');(self.common_dir/'normal.cover').write_bytes(b'wrong')
        x=self.build();self.assertEqual(x['inputs']['race_node']['status'],'unavailable_or_invalid')
        self.assertEqual(x['inputs']['normal_common']['status'],'unavailable_or_invalid');self.assertIsNone(x['attributed_subset']['normal']['complete_subset_statements'])
        self.assertEqual(x['attributed_subset']['normal']['observed_statements'],{'covered':0,'total':2})
        self.assertEqual(x['attributed_subset']['race']['observed_statements'],{'covered':0,'total':3})
        y=self.build(False,False,False);self.assertTrue(all(v['status']=='not_supplied' for v in y['inputs'].values()))
        self.assertIsNone(y['attributed_subset']['normal']['observed_statements'])
        (self.root/'labels/fixture.go').write_text('different')
        with self.assertRaisesRegex(ValueError,'node_source_mismatch'):self.build(False,False,False)

    def test_bindings_reject_tampering(self):
        self.normal();self.race();self.common()
        p=self.node_dir/'node-direct-r25.json';v=json.loads(p.read_bytes());v['expected_statements']=99;store(p,v)
        self.assertEqual(self.build()['inputs']['normal_node']['status'],'unavailable_or_invalid')
        self.normal();p=self.node_dir/'node-direct-r25-bound-manifest.json';store(p,{})
        self.assertEqual(self.build()['inputs']['normal_node']['status'],'unavailable_or_invalid')
        self.normal();p=self.node_dir/'input.json';v=json.loads(p.read_bytes());v['status']='unavailable';store(p,v)
        self.assertEqual(self.build()['inputs']['normal_node']['status'],'unavailable_or_invalid')
        self.normal();p=self.node_dir/'input.json';v=json.loads(p.read_bytes());v['profile_sha256']='bad';store(p,v)
        self.assertEqual(self.build()['inputs']['normal_node']['status'],'unavailable_or_invalid')
        self.common();(self.root/'go.mod').write_text('different')
        self.assertEqual(self.build()['inputs']['normal_common']['status'],'unavailable_or_invalid')

    def test_invalid_roster_and_cli_subject(self):
        bad=dict(self.roster);bad['schema']='wrong'
        with self.assertRaisesRegex(ValueError,'invalid_roster_schema'):
            r.build_report(self.root,self.subject,bad,self.nt,self.ct,self.selectors,None,None,None,None)
        bad=dict(self.roster);bad['node']=[self.node_pkg,self.node_pkg]
        with self.assertRaisesRegex(ValueError,'invalid_roster'):
            r.build_report(self.root,self.subject,bad,self.nt,self.ct,self.selectors,None,None,None,None)
        with patch('sys.argv',['report.py','--checkout',str(self.root),'--subject',self.subject,'--output',str(self.root/'out.json')]),patch.object(r.subprocess,'check_output',return_value='b'*40):
            with self.assertRaisesRegex(ValueError,'checkout_subject_mismatch'):r.main()

    def test_cli_current_attempt_and_no_overwrite(self):
        d=self.root/'.github/coverage/ordinary';d.mkdir(parents=True)
        (d/'common-direct').mkdir();(d/'node-direct-race').mkdir()
        (d/'node-direct-r25.json').write_bytes(self.nt)
        (d/'common-direct/census.json').write_bytes(self.ct)
        (d/'node-direct-race/selectors-r28.json').write_bytes(self.selectors)
        store(self.root/'roster.json',self.roster)
        out=self.root/'out.json'
        with patch('sys.argv',['report.py','--checkout',str(self.root),'--subject',self.subject,'--output',str(out)]),patch.object(r,'HERE',self.root),patch.object(r.subprocess,'check_output',return_value=self.subject):
            r.main()
            self.assertEqual(json.loads(out.read_bytes())['status'],'NOT_EVALUATED')
            initial=out.read_bytes()
            with self.assertRaises(FileExistsError):r.main()
            self.assertEqual(out.read_bytes(),initial)

    def test_roster_matches_existing_workflow(self):
        roster=json.loads((r.HERE/'roster.json').read_bytes())
        text=(r.HERE.parents[2]/'workflows/drwa-ci.yml').read_text()
        for key,label,size in [('NODE_REPORT_PACKAGES','node',34),('COMMON_REPORT_PACKAGES','common',5)]:
            m=re.search(r'^([ ]*)'+key+r': >-\n((?:\1[ ]{2}\S.*\n)+)',text,re.M)
            self.assertIsNotNone(m)
            self.assertEqual(m.group(2).split(),roster[label]);self.assertEqual(len(roster[label]),size)

    def test_module_inputs_do_not_cross_credit(self):
        self.normal();raw=(self.node_dir/'coverage-input.cover').read_bytes()+self.profile(self.common_file,3,1).split(b'\n',1)[1]
        (self.node_dir/'coverage-input.cover').write_bytes(raw)
        store(self.node_dir/'input.json',{'status':'bound','profile_before':'absent','primary_outcome':'success','profile_sha256':r.sha(raw)})
        self.artifacts(self.node_dir,raw,self.nf,'node-direct-r25.json','node-direct-r25-bound-manifest.json')
        x=self.build(True,False,False)
        self.assertEqual(x['attributed_subset']['normal']['observed_statements'],{'covered':0,'total':2})
        self.assertEqual(x['packages'][-1]['node_primary_mixed_normal'],{'covered':3,'total':3})


if __name__=='__main__':unittest.main()
