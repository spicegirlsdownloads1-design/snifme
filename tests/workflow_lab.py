"""Local-only, deliberately synthetic v5.4 DAM export-workflow lab.
Run: py tests\\workflow_lab.py and open http://127.0.0.1:8767/ .
No real account or AWS APIs used; downloadable ZIP contains a harmless text file.
"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from io import BytesIO
import json
import zipfile

PAGE = '''<!doctype html><html lang="en"><meta charset="utf-8"><title>Trufflehog v5.4 Workflow Lab</title>
<style>body{font:16px system-ui;max-width:680px;margin:50px auto;padding:20px;background:#161c23;color:#f1f4f8}button,a{font:inherit;background:#1f9b87;color:white;border:0;border-radius:8px;padding:12px 18px;cursor:pointer;margin:8px}pre{padding:16px;background:#252f3b;white-space:pre-wrap}</style>
<h1>Local DAM export-workflow fixture</h1>
<p>All requests remain on 127.0.0.1. This is a simulated 202-accepted export followed by polling and an attachment download, not a real signed URL.</p>
<button id="prepare">1. Prepare synthetic export</button><a id="download" href="/media/export?Signature=DUMMY_NOT_REAL&Expires=999999" hidden>2. Download harmless ZIP</a>
<pre id="log">Open the extension, start capture, enable Download observer, and select Prepare.</pre>
<script>
const log=(s)=>document.querySelector('#log').textContent+='\\n'+s;
document.querySelector('#prepare').addEventListener('click',async()=>{
 const r=await fetch('/api/export/create',{method:'POST',headers:{'content-type':'application/json','x-csrf-token':'synthetic-only'},body:JSON.stringify({downloadType:'demo',items:[]})});
 log('POST /api/export/create → '+r.status);
 const s=await fetch('/api/export/status');log('GET /api/export/status → '+s.status);
 if(r.status===202&&s.ok){document.querySelector('#download').hidden=false;log('Use the Download button. Observe referrer attribution and timing confidence.');}
});
</script></html>'''

class Handler(BaseHTTPRequestHandler):
    def _send(self,code,typ,data,extra=None):
        self.send_response(code)
        self.send_header('Content-Type',typ)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','private, max-age=0')
        for k,v in (extra or {}).items():self.send_header(k,v)
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        if self.path!='/api/export/create':return self._send(404,'text/plain',b'Not found')
        length=min(int(self.headers.get('Content-Length','0') or 0),32768)
        self.rfile.read(length)  # Lab only, does not retain or log POST values.
        self._send(202,'application/json',json.dumps({'status':'accepted','demo':True}).encode())
    def do_GET(self):
        if self.path=='/':return self._send(200,'text/html; charset=utf-8',PAGE.encode())
        if self.path=='/api/export/status':return self._send(200,'application/json',b'{"status":"ready","demo":true}')
        if self.path.startswith('/media/export?'):
            buf=BytesIO()
            with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('example.txt','Trufflehog v5.4 — synthetic downloadable file only.\n')
            return self._send(200,'application/zip',buf.getvalue(),{'Content-Disposition':'attachment; filename="synthetic-export.zip"'})
        return self._send(404,'text/plain',b'Not found')
    def log_message(self,*_args):pass
if __name__=='__main__':
    host='127.0.0.1';port=8767
    print(f'Open http://{host}:{port}/ and enable Trufflehog Download Observer for this origin.',flush=True)
    ThreadingHTTPServer((host,port),Handler).serve_forever()
