"""Server integration test. Run: python -m unittest discover -s tests -v"""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from http.server import ThreadingHTTPServer

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'console'))
import server as sg

class ConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        sg.STATE=Path(cls.temp.name)
        sg.DB_FILE=sg.STATE/'test.db'
        os.environ['SENTINEL_ADMIN_PASSWORD']='SafeTestOnlyPassword2026!'
        sg.initialize()
        cls.http=ThreadingHTTPServer(('127.0.0.1',0),sg.Handler)
        cls.url='http://127.0.0.1:'+str(cls.http.server_port)
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown();cls.http.server_close();cls.thread.join(timeout=2)
        cls.temp.cleanup()

    def request(self,path,payload=None,headers=None):
        args=dict(headers or {})
        if payload is not None: args['Content-Type']='application/json'
        req=urllib.request.Request(self.url+path,data=json.dumps(payload).encode() if payload is not None else None,headers=args)
        try:
            with urllib.request.urlopen(req,timeout=3) as resp:
                return resp.status,json.loads(resp.read()),resp.headers
        except urllib.error.HTTPError as resp:
            return resp.code,json.loads(resp.read()),resp.headers

    def test_health_and_auth_enroll_policy_events(self):
        status,body,_=self.request('/api/health')
        self.assertEqual(status,200)
        self.assertEqual(body['status'],'ok')
        status,_,_=self.request('/api/admin/summary')
        self.assertEqual(status,401)
        status,_,_=self.request('/api/admin/login',{'username':'admin','password':'wrong password'})
        self.assertEqual(status,401)
        status,auth,headers=self.request('/api/admin/login',{'username':'admin','password':'SafeTestOnlyPassword2026!'})
        self.assertEqual(status,200)
        cookie=headers['Set-Cookie'].split(';',1)[0]
        csrf=auth['csrf']
        ah={'Cookie':cookie,'X-CSRF-Token':csrf}
        status,_,_=self.request('/api/admin/enroll',{'name':'TEST-LAPTOP'}, {'Cookie':cookie})
        self.assertEqual(status,403)
        status,device,_=self.request('/api/admin/enroll',{'name':'TEST-LAPTOP'},ah)
        self.assertEqual(status,201)
        token=device['device_token']
        status,policy,_=self.request('/api/agent/policy',headers={'Authorization':'Bearer '+token})
        self.assertEqual(status,200)
        self.assertEqual(policy['policy']['mode'],'monitor')
        status,_,_=self.request('/api/agent/events',{'events':[{'kind':'web','action':'blocked','domain':'example.invalid','reason':'Restricted domain'}]}, {'Authorization':'Bearer '+token})
        self.assertEqual(status,200)
        status,summary,_=self.request('/api/admin/summary',headers={'Cookie':cookie})
        self.assertGreaterEqual(summary['blocked_24h'],1)
        self.assertEqual(summary['total_devices'],1)
        current=policy['policy'];current['mode']='monitor'
        status,save,_=self.request('/api/admin/policy',current,ah)
        self.assertEqual(status,200)
        self.assertEqual(save['policy']['mode'],'monitor')
        status,_,_=self.request('/api/admin/policy',{**current,'blocked_domains':['https://invalid.example/path']},ah)
        self.assertEqual(status,400)

    def test_assets(self):
        status,_,headers=self.request('/api/health')
        self.assertEqual(headers['X-Content-Type-Options'],'nosniff')
        req=urllib.request.Request(self.url+'/')
        with urllib.request.urlopen(req,timeout=3) as resp:
            self.assertIn('text/html',resp.headers['Content-Type'])
            self.assertIn(b'SentinelGate',resp.read())

    def test_policy_validation(self):
        value=sg.validate_policy(sg.DEFAULT_POLICY)
        self.assertIn('example.invalid',value['blocked_domains'])
        for bad in ('http://site.example','*.example.com','../test'):
            with self.assertRaises(ValueError): sg.validate_policy({**sg.DEFAULT_POLICY,'blocked_domains':[bad]})

if __name__=='__main__':unittest.main()

# Additional local bridge + central telemetry smoke test. Runs independently of Windows.
class BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        sg.STATE=Path(cls.temp.name)/'server-state'
        sg.DB_FILE=sg.STATE/'test.db'
        os.environ['SENTINEL_ADMIN_PASSWORD']='BridgeTestPassword2026!'
        sg.initialize()
        cls.console=ThreadingHTTPServer(('127.0.0.1',0),sg.Handler)
        cls.url='http://127.0.0.1:'+str(cls.console.server_port)
        cls.console_thread=threading.Thread(target=cls.console.serve_forever,daemon=True)
        cls.console_thread.start()
        def req(path,payload=None,headers=None):
            data=json.dumps(payload).encode() if payload is not None else None
            hdr=dict(headers or {})
            if data is not None: hdr['Content-Type']='application/json'
            with urllib.request.urlopen(urllib.request.Request(cls.url+path,data=data,headers=hdr),timeout=3) as r:
                return json.loads(r.read()),r.headers
        login,head=req('/api/admin/login',{'username':'admin','password':'BridgeTestPassword2026!'})
        cls.cookie=head['Set-Cookie'].split(';')[0]
        device,_=req('/api/admin/enroll',{'name':'BRIDGE-TEST'}, {'Cookie':cls.cookie,'X-CSRF-Token':login['csrf']})
        cls.device_id=device['device_id']
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'agent'))
        import agent as ag
        cls.agent=ag
        ag.DATA=Path(cls.temp.name)/'agent-state';ag.DATA.mkdir()
        ag.QUEUE=ag.DATA/'events.jsonl'
        ag.CACHE=ag.DATA/'policy.json'
        ag.CONFIG={'server_url':cls.url,'device_id':device['device_id'],'device_token':device['device_token'],'bridge_token':'ABCdef0123456789___BRIDGE_SECRET'}
        ag.POLICY=sg.DEFAULT_POLICY.copy()
        cls.bridge=ThreadingHTTPServer(('127.0.0.1',0),ag.BridgeHandler)
        cls.bridge_url='http://127.0.0.1:'+str(cls.bridge.server_port)
        cls.bridge_thread=threading.Thread(target=cls.bridge.serve_forever,daemon=True)
        cls.bridge_thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.bridge.shutdown();cls.bridge.server_close();cls.bridge_thread.join(timeout=2)
        cls.console.shutdown();cls.console.server_close();cls.console_thread.join(timeout=2)
        cls.temp.cleanup()
    def test_bridge_auth_and_telemetry(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.bridge_url+'/api/policy',timeout=3)
        self.assertEqual(ctx.exception.code,401)
        origin='chrome-extension://abcdefghij'
        headers={'Origin':origin,'X-Sentinel-Bridge':self.agent.CONFIG['bridge_token']}
        with urllib.request.urlopen(urllib.request.Request(self.bridge_url+'/api/policy',headers=headers),timeout=3) as resp:
            info=json.loads(resp.read())
            self.assertEqual(info['policy']['mode'],'monitor')
            self.assertEqual(resp.headers['Access-Control-Allow-Origin'],origin)
        payload={'kind':'upload','action':'blocked','domain':'sample.example','extension':'sql','size':15,'reason':'Restricted file extension'}
        with urllib.request.urlopen(urllib.request.Request(self.bridge_url+'/api/event',data=json.dumps(payload).encode(),headers={**headers,'Content-Type':'application/json'}),timeout=3) as r:
            self.assertEqual(r.status,202)
        self.agent.flush_events()
        with urllib.request.urlopen(urllib.request.Request(self.url+'/api/admin/events',headers={'Cookie':self.cookie}),timeout=3) as r:
            events=json.loads(r.read())['events']
        self.assertTrue(any(e['domain']=='sample.example' and e['device_id']==self.device_id for e in events))
