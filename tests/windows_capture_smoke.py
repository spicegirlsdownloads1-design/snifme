"""Trufflehog v3.8 local-only acceptance fixture. Python stdlib; no dependencies.

Windows: cd to extension folder; python tests\\windows_capture_smoke.py
Open Chrome yourself and follow on-screen checklist. Ctrl+C stops the server.
"""
import argparse
from functools import partial
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import webbrowser

class Handler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print('[fixture]', fmt % args)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run Trufflehog safe local gallery')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--no-open', action='store_true')
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    server = ThreadingHTTPServer(('127.0.0.1', args.port), partial(Handler, directory=str(directory)))
    url = f'http://127.0.0.1:{args.port}/local-test-gallery.html'
    print('\nTrufflehog Intelligence v3.8 — Windows installed-Chrome verification')
    print('This fixture is local-only and contains no secrets. It will not scan other websites.')
    print('1. Load the unpacked extension in chrome://extensions and open:', url)
    print('2. Grant this site access and start capture from the Trufflehog popup.')
    print('3. Open DevTools (F12) on this local page, then reload it (Ctrl+R).')
    print('4. Open Auto-scanned files: JS/CSS/HTML/JSON should appear among eligible resources.')
    print('5. Check that scanner heartbeat is fresh and status reflects exclusions accurately.')
    print('6. Press Add gallery card. Use Recheck & restore capture and Run full self-test.')
    print('7. Click Send test notification (synthetic), stop, and check Evidence Vault.')
    print('8. Fully close Chrome, reopen it, and verify the archived session still exists.')
    print('9. If any check fails, copy the self-test report; it contains no secrets.')
    print('Press Ctrl+C to stop the local fixture server.\n')
    if not args.no_open:
        try: webbrowser.open(url)
        except Exception: pass
    try: server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt: print('\nLocal fixture stopped.')
    finally: server.server_close()
