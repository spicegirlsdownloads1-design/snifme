"""Trufflehog v6.0 deterministic LOCAL fixture. Only binds 127.0.0.1:8770."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
class Handler(BaseHTTPRequestHandler):
    def send(self, status, content, mime, attachment=False):
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(content)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        if attachment: self.send_header('Content-Disposition','attachment; filename="synthetic-local.txt"')
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(content)
    def do_GET(self):
        route=self.path.split('?',1)[0]
        if route in ('/v60-lab.html','/v60-lab.js','/v60-lab.css','/v60-lab.json','/v60-lab.svg'):
            kind={'html':'text/html; charset=utf-8','js':'text/javascript','css':'text/css','json':'application/json','svg':'image/svg+xml'}
            ext=route.rsplit('.',1)[-1]
            return self.send(200,(ROOT/route.lstrip('/')).read_bytes(),kind[ext])
        if route=='/v60-state':return self.send(200,b'{"status":"ready","synthetic":true}', 'application/json')
        if route=='/v60-export':
            self.send_response(302)
            self.send_header('Location','/v60-file')
            self.send_header('Cache-Control','no-store')
            self.end_headers();return
        if route=='/v60-file':return self.send(200,b'TRUFFLEHOG V6 LOCAL DEMONSTRATION. NO MEDIA FILE.\n','application/octet-stream',True)
        return self.send(404,b'Not found','text/plain')
    def do_POST(self):
        # Consume only a bounded synthetic body; neither print nor save it.
        length=int(self.headers.get('Content-Length','0'))
        if length>8192:return self.send(413,b'Too large','text/plain')
        if length:self.rfile.read(length)
        if self.path.split('?',1)[0]=='/v60-job':return self.send(202,b'{"status":"accepted","synthetic":true}', 'application/json')
        return self.send(404,b'Not found','text/plain')
    def log_message(self, fmt, *args):
        # Do not log URLs, even locally.
        print('[local fixture]', self.command, 'served')
if __name__=='__main__':
    print('Trufflehog v6.0 LOCAL capture benchmark: http://127.0.0.1:8770/v60-lab.html',flush=True)
    print('1. Chrome: load unpacked extension and grant localhost permission.',flush=True)
    print('2. Open fixture. Start capture AND enable Download Observer.',flush=True)
    print('3. Open DevTools on fixture tab BEFORE reloading.',flush=True)
    print('4. Reload, press Run synthetic export, then inspect Overview > Local capture benchmark.',flush=True)
    print('5. Stop capture, inspect Evidence Vault and standard Capture acceptance.',flush=True)
    print('Ctrl+C to stop. Does not connect to AWS/DAM/third-party services.',flush=True)
    srv=ThreadingHTTPServer(('127.0.0.1',8770),Handler)
    try:srv.serve_forever()
    except KeyboardInterrupt:pass
    finally:srv.server_close()
