r"""Opt-in extension startup test using Playwright Chromium, not an external website.

Windows:
    py -m pip install playwright
    py -m playwright install chromium
    py tests\windows_extension_startup.py

A PASS confirms the installed extension worker and popup loaded in this isolated
Chromium profile. It does not validate Windows notification delivery or DevTools
response interception; follow the manual README checklist for those.
"""
import json
import os
import tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT/'manifest.json').read_text(encoding='utf-8'))

with tempfile.TemporaryDirectory(prefix='trufflehog-chromium-test-') as profile:
    with sync_playwright() as playwright:
        args = [f'--disable-extensions-except={ROOT}', f'--load-extension={ROOT}', '--no-first-run']
        if os.name != 'nt':
            args += ['--no-sandbox','--disable-dev-shm-usage']
        kwargs = {}
        if os.environ.get('THI_CHROMIUM_BIN'):
            kwargs['executable_path'] = os.environ['THI_CHROMIUM_BIN']
        elif os.name != 'nt' and Path('/usr/bin/chromium').exists():
            kwargs['executable_path'] = '/usr/bin/chromium'
        ctx = playwright.chromium.launch_persistent_context(profile, headless=False, args=args, timeout=20000, **kwargs)
        try:
            worker = next((w for w in ctx.service_workers if w.url.startswith('chrome-extension://')), None)
            if not worker:
                try:worker = ctx.wait_for_event('serviceworker', predicate=lambda w:w.url.startswith('chrome-extension://'),timeout=15000)
                except PlaywrightTimeout as exc:raise RuntimeError('No extension service worker observed. Check Chromium extension loading / policy.') from exc
            extension_id=worker.url.split('/')[2]
            result=worker.evaluate('''() => ({version: chrome.runtime.getManifest().version, storage: !!chrome.storage?.local,
                                        hasPermissions: !!chrome.permissions, hasNotifications: !!chrome.notifications})''')
            assert result['version']==MANIFEST['version'], result
            assert result['storage'] and result['hasPermissions'] and result['hasNotifications'], result
            popup=ctx.new_page()
            popup.goto(f'chrome-extension://{extension_id}/popup.html', wait_until='domcontentloaded',timeout=12000)
            popup.get_by_text('Trufflehog',exact=False).first.wait_for(timeout=5000)
            print('PASS: extension service worker loaded, manifest '+result['version']+' verified, popup rendered.')
            print('PASS: storage, permissions and notifications APIs available. No website scanned.')
            print('MANUAL STEPS: run full extension self-test and send a test notification on your Windows installation.')
        finally:
            ctx.close()
