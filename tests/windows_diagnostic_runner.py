"""Independent Chrome/Chromium startup diagnostic, no third-party requests.

Windows (inside the unpacked extension folder):
    py tests\\windows_diagnostic_runner.py
    py tests\\windows_diagnostic_runner.py --chrome "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"

Reports baseline browser launch separately from extension load. The integration
stage launches a disposable profile and does not scan real websites. It does NOT
establish working DevTools response interception or Windows notification display.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def browser_path(supplied):
    if supplied:return Path(supplied)
    if os.name=='nt':
        candidates=[Path(os.environ.get('PROGRAMFILES','C:\\Program Files'))/'Google/Chrome/Application/chrome.exe',
          Path(os.environ.get('PROGRAMFILES(X86)','C:\\Program Files (x86)'))/'Google/Chrome/Application/chrome.exe',
          Path(os.environ.get('LOCALAPPDATA',''))/'Google/Chrome/Application/chrome.exe']
    else:candidates=[Path('/usr/bin/chromium'),Path('/usr/bin/google-chrome')]
    return next((p for p in candidates if p.is_file()),None)

def child_run(browser,timeout):
    # Return one short result to avoid logging browser console output or content.
    from playwright.sync_api import sync_playwright
    with tempfile.TemporaryDirectory(prefix='thi-extension-check-') as profile:
        with sync_playwright() as p:
            args=[f'--disable-extensions-except={ROOT}',f'--load-extension={ROOT}','--no-first-run','--no-default-browser-check']
            if os.name!='nt':args.extend(['--no-sandbox','--disable-dev-shm-usage'])
            ctx=p.chromium.launch_persistent_context(profile,headless=False,executable_path=str(browser),args=args,timeout=timeout*1000)
            try:
                worker=next((x for x in ctx.service_workers if x.url.startswith('chrome-extension://')),None)
                if worker is None:
                    worker=ctx.wait_for_event('serviceworker',predicate=lambda w:w.url.startswith('chrome-extension://'),timeout=timeout*1000)
                version=worker.evaluate('chrome.runtime.getManifest().version')
                if version!='4.3.0':raise RuntimeError('Manifest version mismatch')
                eid=worker.url.split('/')[2]
                popup=ctx.new_page()
                popup.goto('chrome-extension://'+eid+'/popup.html',wait_until='domcontentloaded',timeout=timeout*1000)
                popup.get_by_text('Trufflehog',exact=False).first.wait_for(timeout=timeout*1000)
                return {'status':'PASS','detail':'Service worker registered and popup rendered (no site capture tested).'}
            finally:ctx.close()

def main():
    p=argparse.ArgumentParser(description='Local Chrome startup check for Trufflehog Intelligence v4.3')
    p.add_argument('--chrome',help='Path to Chrome/Chromium binary (uses an installed default if omitted)')
    p.add_argument('--timeout',type=int,default=12,help='Maximum seconds per browser stage (5-60)')
    p.add_argument('--_child',action='store_true',help=argparse.SUPPRESS)
    a=p.parse_args()
    timeout=min(60,max(5,a.timeout)); chrome=browser_path(a.chrome)
    if a._child:
        try: print(json.dumps(child_run(chrome,timeout)));return 0
        except Exception as exc:
            print(json.dumps({'status':'FAIL','detail':str(exc)[:160]}));return 2
    report={'version':'4.3.0','date':datetime.now(timezone.utc).isoformat(),'checks':[],'limitations':'No live DevTools response capture, notification display or IndexedDB persistence tested.'}
    def add(name,status,detail):
        report['checks'].append({'name':name,'status':status,'detail':detail})
    try:
        manifest=json.loads((ROOT/'manifest.json').read_text(encoding='utf-8'))
        assert manifest.get('version')=='4.3.0' and manifest.get('manifest_version')==3
        assert (ROOT/'background.js').is_file() and (ROOT/'popup.html').is_file()
        add('package','PASS','Manifest V3, v4.3.0, background script and popup present.')
    except Exception as e:
        add('package','FAIL',str(e)[:100]);print(json.dumps(report,indent=2));return 1
    if not chrome or not chrome.is_file():
        add('browser baseline','BLOCKED','No installed Chrome/Chromium binary found. Specify --chrome.');print(json.dumps(report,indent=2));return 2
    try:
        with tempfile.TemporaryDirectory(prefix='thi-browser-baseline-') as profile:
            cmd=[str(chrome),'--headless=new','--no-first-run','--no-default-browser-check','--disable-gpu','--disable-extensions',f'--user-data-dir={profile}','--dump-dom','about:blank']
            if os.name!='nt':cmd+=['--no-sandbox','--disable-dev-shm-usage']
            result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout)
            if result.returncode!=0 or b'<html' not in result.stdout.lower():
                raise RuntimeError('Browser baseline did not render a blank page')
        add('browser baseline','PASS','Blank local page opened without extensions.')
    except (subprocess.TimeoutExpired,RuntimeError,OSError) as e:
        add('browser baseline','BLOCKED',('Browser startup timed out' if isinstance(e,subprocess.TimeoutExpired) else 'Browser failed to launch a local blank page')+'; cannot attribute failure to the extension.')
        add('extension startup','SKIP','Browser baseline was not available.')
        print(json.dumps(report,indent=2));return 2
    try:
        import playwright  # noqa
    except ImportError:
        add('extension startup','SKIP','Install Playwright: py -m pip install playwright')
        print(json.dumps(report,indent=2));return 2
    cmd=[sys.executable,str(Path(__file__).resolve()),'--_child','--chrome',str(chrome),'--timeout',str(timeout)]
    try:
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout*3)
        try: data=json.loads(r.stdout.decode('utf-8').strip().splitlines()[-1]);add('extension startup',data.get('status','FAIL'),str(data.get('detail',''))[:160])
        except Exception: add('extension startup','FAIL','Extension worker/popup stage did not return a structured result.')
    except subprocess.TimeoutExpired:
        add('extension startup','BLOCKED','Isolated browser extension stage timed out; see Chrome policies, display and permissions.')
    print(json.dumps(report,indent=2));return 0 if all(c['status']=='PASS' for c in report['checks']) else 2

if __name__=='__main__':sys.exit(main())
