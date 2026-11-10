from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[2]
html=(ROOT/'portal/prototypes/gateway-operations.html').read_text(encoding='utf8')
with sync_playwright() as p:
 browser=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
 page=browser.new_page(viewport={'width':1536,'height':1050},accept_downloads=True)
 errs=[]
 page.on('pageerror',lambda e:errs.append(str(e)))
 page.set_content(html,wait_until='load')
 page.locator('[data-page="traffic"]').click()
 assert 'Request / Response' in page.locator('#pageContent').inner_text()
 # 200: two hops, each with one request + one response and headers/body.
 page.locator('[data-trace="TRC-69d314"]').first.click()
 assert page.locator('.exchange-hop').count()==2
 assert page.locator('[data-message-kind="request"]').count()==2
 assert page.locator('[data-message-kind="response"]').count()==2
 assert page.locator('[data-message-stage="clientResponse"]').count()==1
 assert page.locator('[data-message-stage="external"]').count()==1
 assert page.locator('text=DEMO-UPSTREAM-282').count()>=1
 assert page.locator('[data-comparison="true"]').count()==1
 assert page.locator('text=[RESTRICTED: viewer role]').count()>0
 page.locator('#closeDrawer').click()
 # 403: gateway-generated response still exists while no provider exchange occurred.
 page.locator('[data-trace="TRC-69d316"]').first.click()
 assert page.locator('text=NOT_SENT').count()>0
 assert page.locator('text=NOT_REACHED').count()>0
 assert 'HTTP/1.1 403' in page.locator('[data-message-stage="clientResponse"]').inner_text()
 page.locator('#closeDrawer').click()
 # 504: an outbound request was attempted; no provider response was observed.
 page.locator('[data-trace="TRC-69d317"]').first.click()
 assert page.locator('text=NO_RESPONSE_OBSERVED').count()>0
 assert page.locator('text=操作结果 UNKNOWN').count()>0
 assert 'HTTP/1.1 504' in page.locator('[data-message-stage="clientResponse"]').inner_text()
 page.locator('#closeDrawer').click()
 # Privileged demo role may preview redacted examples and export a safe JSON report.
 page.locator('#role').select_option('engineer')
 page.locator('[data-trace="TRC-69d317"]').first.click()
 assert 'DEMO-SHP-1024' in page.locator('.drawer.message-open').inner_text()
 assert '[REDACTED: provider access token]' in page.locator('.drawer.message-open').inner_text()
 page.wait_for_timeout(300)
 page.locator('#drawerBody').evaluate('(el) => el.scrollTop = 430')
 page.screenshot(path=str(ROOT/'portal/previews/10_message_inspector.png'))
 with page.expect_download() as download:page.locator('[data-action="export-diag"]').click()
 assert download.value.suggested_filename.endswith('_SANITIZED.json')
 assert not errs,errs
 print('PASS 15 checks: paired 200, denied 403, timeout 504, mock role isolation, redacted export, JS errors')
 browser.close()
