#!/usr/bin/env python3
"""Offline-only UI smoke tests; NEVER call network/Gateway/Gatekeeper.

Uses Chromium set_content intentionally (this runner may block local-file navigation).
Only checks mock UX interactions and DOM invariants.
"""
from pathlib import Path
import re, sys, datetime
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[2]
HTML=ROOT/'portal/prototypes/gateway-operations.html'
PREVIEW=ROOT/'portal/previews'
PREVIEW.mkdir(parents=True,exist_ok=True)
results=[]
def ck(label,condition):
 assert condition,label
 results.append(label)
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
 page=browser.new_page(viewport={'width':1440,'height':900},device_scale_factor=1,accept_downloads=True)
 errors=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.set_content(HTML.read_text(encoding='utf-8'),wait_until='load')
 ck('01 title', 'Gateway Console' in page.title())
 ck('02 eighteen navigable pages',page.locator('[data-page]').count()==18)
 ck('03 no real network references', not any(w in HTML.read_text() for w in ['fetch(', 'XMLHttpRequest(', 'WebSocket(', 'navigator.sendBeacon(']))
 ck('04 demo banner',page.locator('.demo-pill').inner_text().startswith('DEMO DATA'))
 page.screenshot(path=str(PREVIEW/'01_dashboard.png'),full_page=True)
 # dashboard should not have overlapping side cards
 a=page.locator('.split .panels').nth(0).bounding_box();b=page.locator('.split .panels').nth(1).bounding_box()
 ck('05 dashboard columns do not overlap',a['x']+a['width']<=b['x']+1)
 # routes
 page.locator('[data-page="routes"]').click();ck('06 routes page',page.locator('h1').inner_text()=='API 路由与上游')
 ck('07 production route count',page.locator('#routeRows tr[data-route]').count()==6)
 page.locator('#routeSearch').fill('FedEx');ck('08 route search',page.locator('#routeRows tr[data-route]').count()==2)
 page.locator('#routeSearch').fill('');page.locator('#routePool').select_option('Egress');ck('09 route domain filter',page.locator('#routeRows tr[data-route]').count()==3)
 page.locator('#routePool').select_option('all');page.locator('#routeRows tr[data-route]').first.click();ck('10 route details opened','open' in page.locator('#drawer').get_attribute('class'))
 ck('11 credential secret masked','不可查看' in page.locator('#drawerBody').inner_text())
 page.keyboard.press('Escape');ck('12 esc closes drawer','open' not in page.locator('#drawer').get_attribute('class'))
 page.screenshot(path=str(PREVIEW/'02_routes.png'),full_page=True)
 # policies
 page.locator('[data-page="policies"]').click();ck('13 policy rows',page.locator('#policyRows tr[data-policy]').count()==6)
 page.locator('#policyDecision').select_option('deny');ck('14 policy decision filters',page.locator('#policyRows tr[data-policy]').count()==0)
 page.locator('#env').select_option('staging');ck('15 stage shows denial',page.locator('#policyRows tr[data-policy]').count()==2)
 page.locator('#policyRows tr[data-policy]').first.click();ck('16 policy detail readable','授权操作' in page.locator('#drawerBody').inner_text());page.keyboard.press('Escape')
 page.screenshot(path=str(PREVIEW/'03_policies.png'),full_page=True)
 # trace
 page.locator('#env').select_option('production');page.locator('[data-page="traffic"]').click();ck('17 trace rows',page.locator('#traceRows tr[data-trace]').count()==9)
 page.locator('#trafficStatus').select_option('auth');ck('18 auth status filter',page.locator('#traceRows tr[data-trace]').count()==2)
 page.locator('#trafficStatus').select_option('all');page.locator('[data-trace="TRC-69d317"]').first.click();ck('19 UNKNOWN on 504','UNKNOWN' in page.locator('#drawerBody').inner_text())
 ck('20 redacted token','[REDACTED:' in page.locator('#drawerBody').inner_text());page.keyboard.press('Escape')
 page.screenshot(path=str(PREVIEW/'04_traffic.png'),full_page=True)
 # release flow
 page.locator('[data-page="releases"]').click();ck('21 viewer approval disabled',not page.locator('[data-action="approve-release"]').is_enabled())
 page.locator('#role').select_option('engineer');ck('22 engineer approval disabled',not page.locator('[data-action="approve-release"]').is_enabled())
 page.locator('#role').select_option('reviewer');ck('23 reviewer approval enabled',page.locator('[data-action="approve-release"]').is_enabled())
 page.locator('[data-action="approve-release"]').click();ck('24 explicit confirmation','open' in page.locator('#confirmOverlay').get_attribute('class'))
 page.locator('#confirmAccept').click();ck('25 mock approval reflected','已审批' in page.locator('.release-row.selected').inner_text())
 page.locator('#role').select_option('operator');ck('26 operator deploy enabled',page.locator('[data-action="deploy-release"]').is_enabled())
 page.locator('[data-action="deploy-release"]').click();page.locator('#confirmAccept').click();ck('27 mock deploy reflected','已生效' in page.locator('.release-row.selected').inner_text())
 ck('28 operator rollback enabled',page.locator('[data-action="rollback-release"]').is_enabled())
 page.screenshot(path=str(PREVIEW/'05_releases.png'),full_page=True)
 page.locator('[data-action="rollback-release"]').click();page.locator('#confirmAccept').click();ck('29 mock rollback reflected','历史版本' in page.locator('.release-row.selected').inner_text())
 # instance failure
 page.locator('[data-page="instances"]').click();ck('30 pool cards',page.locator('.pool-card').count()==3)
 page.locator('[data-action="fail-instance"]').click();page.locator('#confirmAccept').click();ck('31 simulated failure',page.locator('.instance-pill.fail').count()==1)
 page.locator('[data-action="reset-instances"]').click();ck('32 restored',page.locator('.instance-pill.fail').count()==0)
 page.screenshot(path=str(PREVIEW/'06_instances.png'),full_page=True)
 # Mobile responsiveness
 mobile=browser.new_page(viewport={'width':390,'height':844},device_scale_factor=1)
 mobile.set_content(HTML.read_text(encoding='utf-8'),wait_until='load')
 ck('33 responsive nav visible',mobile.locator('[data-page="routes"]').is_visible())
 mobile.locator('[data-page="routes"]').click();ck('34 mobile routes rendered',mobile.locator('#routeRows tr[data-route]').count()==6)
 ck('35 no JS errors',not errors)
 browser.close()
report=['# IDP Gateway Operations — Browser Mock Interaction Tests',f'Executed UTC: {datetime.datetime.now(datetime.timezone.utc).isoformat()}', 'Runtime target: local inline HTML via Chromium set_content (no backend access)',f'Mock browser checks: {len(results)} PASS, 0 FAIL', 'Gateway / Gatekeeper / real provider / production UI integration: NOT_RUN','',*['PASS '+s for s in results]]
(ROOT/'tests/evidence/ux-prototype-browser-tests.txt').write_text('\n'.join(report)+'\n',encoding='utf-8')
print('\n'.join(report))
