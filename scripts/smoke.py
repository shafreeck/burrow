import subprocess,tempfile,pathlib,re,time,json,urllib.request,threading,http.server,os
base=pathlib.Path(__file__).resolve().parent.parent/'dist'
class Target(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'burrow binary e2e accepted')
 def log_message(self,*args):pass
origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target)
threading.Thread(target=origin.serve_forever,daemon=True).start()
with tempfile.TemporaryDirectory(prefix='burrow-accept-') as folder:
 logpath=pathlib.Path(folder)/'server.log'
 with logpath.open('w') as log:
  server=subprocess.Popen([str(base/'burrow-server'),'--listen','127.0.0.1:0','--bind','http://127.0.0.1:0','--debug'],cwd=folder,stdout=log,stderr=log)
  agent=None
  try:
   for _ in range(100):
    text=logpath.read_text();cp=re.search(r'control plane: http://(127.0.0.1:\d+)',text);proxy=re.search(r'proxy inbound: http://(127.0.0.1:\d+)',text)
    if cp and proxy:break
    time.sleep(.05)
   assert cp and proxy,text
   cpurl='http://'+cp[1]
   direct=urllib.request.build_opener(urllib.request.ProxyHandler({}))
   assert not json.load(direct.open(cpurl+'/healthz'))['agent_connected']
   env=dict(os.environ);env.pop('BURROW_UPSTREAM',None);env.pop('BURROW_TOKEN',None)
   with (pathlib.Path(folder)/'agent.log').open('w') as alog:
    agent=subprocess.Popen([str(base/'burrow-agent'),'--server','ws://'+cp[1]+'/ws'],cwd=folder,stdout=alog,stderr=alog,env=env)
    for _ in range(100):
     health=json.load(direct.open(cpurl+'/healthz'))
     if health['agent_connected']:break
     time.sleep(.05)
    assert health['agent_connected']
    # raw CONNECT avoids urllib's NO_PROXY loopback bypass.
    import socket
    with socket.create_connection(tuple([proxy[1].split(':')[0],int(proxy[1].split(':')[1])]),timeout=3) as conn:
     port=origin.server_address[1]
     conn.sendall(f'CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n'.encode())
     stream=conn.makefile('rb');assert b'200' in stream.readline()
     while stream.readline()!=b'\r\n':pass
     conn.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
     assert b'burrow binary e2e accepted' in stream.read()
    diagnostics=json.load(direct.open(cpurl+'/diagnostics'));assert len(diagnostics['agents'])==1
    print('PASS binary origin -> authenticated agent -> HTTP CONNECT -> local target; diagnostics peer version:',diagnostics['agents'][0]['version'])
  finally:
   if agent:agent.terminate();agent.wait(timeout=5)
   server.terminate();server.wait(timeout=5)
origin.shutdown();origin.server_close()
