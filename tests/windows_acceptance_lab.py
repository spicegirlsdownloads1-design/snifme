"""Local Trufflehog acceptance fixture. Uses Python standard library only."""
from functools import partial
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import argparse

class Handler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print('[acceptance fixture]', fmt % args)

if __name__ == '__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--port',type=int,default=8765);args=ap.parse_args()
    base=Path(__file__).resolve().parent
    srv=ThreadingHTTPServer(('127.0.0.1',args.port),partial(Handler,directory=str(base)))
    url=f'http://127.0.0.1:{args.port}/acceptance-lab.html'
    print('Trufflehog Intelligence v5.0 — LOCAL TEST. No external requests or real secrets.')
    print('1. Open in installed Chrome:',url)
    print('2. Grant only this local site access and start capture.')
    print('3. Open DevTools (F12) on the fixture tab BEFORE reloading it.')
    print('4. Reload. Click Add synthetic asset. Check Overview > Capture acceptance.')
    print('5. Network capture / DevTools response inspection should be observed.')
    print('6. Stop capture and re-run acceptance: vault readback should pass.')
    print('7. Press Send test notification separately; visually verify its Windows banner.')
    print('8. Export acceptance JSON; PASS applies only to the observed parts.')
    print('Ctrl+C to stop. All data stays on localhost.')
    try:srv.serve_forever()
    except KeyboardInterrupt:pass
    finally:srv.server_close()
