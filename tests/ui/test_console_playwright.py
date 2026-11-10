"""Offline-only browser checks for IDP Gateway Console V1.0 mock.
Requires playwright and Chromium. No network requests or gateway dependencies.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[2]
PROTO=ROOT/'portal/prototypes/gateway-operations.html'
PREV=ROOT/'portal/previews'
PREV.mkdir(parents=True,exist_ok=True)
PAGES=['overview','catalog','gateways','routes','backends','providers','policies','llm','llmsecurity','llmkeys','llmanalytics','mcp','mcpplay','a2a','traffic','releases','instances','tools']

def test():
    checks=[]; errors=[]
    def check(label, condition):
        checks.append((label,bool(condition)))
        if not condition: raise AssertionError(label)
    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,executable_path='/usr/bin/chromium', args=['--no-sandbox'])
        page=browser.new_page(viewport={'width':1440,'height':900}, device_scale_factor=1)
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.set_content(PROTO.read_text(encoding='utf-8'))
        check('initial dashboard',page.locator('h1').inner_text().strip()=='Gateway Operations Overview')
        for key in PAGES:
            page.locator(f'[data-page="{key}"]').click()
            check('page '+key, bool(page.locator('h1').inner_text().strip()) and page.locator(f'[data-page="{key}"]').get_attribute('aria-current')=='page')
        # functionality of resources / detail drawer
        page.locator('[data-page="providers"]').click()
        page.locator('[data-feature-detail^="provider:"]').first.click()
        check('provider detail drawer', page.locator('#drawer').evaluate('(x)=>x.classList.contains("open")'))
        page.locator('#closeDrawer').click()
        page.locator('#featureSearch').fill('UPS')
        check('provider search filtering',page.locator('.feature-table tbody tr:visible').count()==1)
        # viewer cannot create draft
        page.locator('[data-page="catalog"]').click()
        page.locator('[data-feature-action="wizard-next"]').click()
        page.locator('[data-feature-action="wizard-next"]').click()
        page.locator('[data-feature-action="wizard-create"]').click()
        check('viewer blocked from creating draft','请切换 Engineer' in page.locator('#toasts').inner_text())
        # engineer can create draft for matching provider/account, staging
        page.locator('#role').select_option('engineer')
        page.locator('[data-feature-action="wizard-create"]').click()
        check('engineer creates local draft',page.locator('.feature-activity').filter(has_text='DEMO-4201').count()>=1)
        check('draft never published',page.locator('[data-page="releases"]').count()==1)
        # safety rejects provider mismatch
        page.locator('[data-feature-action="wizard-next"]').click()
        page.locator('[data-feature-action="wizard-next"]').click()
        page.evaluate("featureState.form.account='ups/acct-04'")
        page.locator('[data-feature-action="wizard-create"]').click()
        check('account/provider mismatch rejected','提供商不一致' in page.locator('#toasts').inner_text())
        # feature tab switches
        tabs={'llm':['models','providers','strategy'],'llmsecurity':['policies','guardrails'],'llmkeys':['keys','clients'],'llmanalytics':['usage','logs'],'mcp':['servers','tools','policies'],'tools':['cel','config','settings']}
        for k, names in tabs.items():
            page.locator(f'[data-page="{k}"]').click()
            for name in names:
                page.locator(f'[data-feature-tab="{k}:{name}"]').click()
                check(f'subtab {k}/{name}',page.locator(f'[data-feature-tab="{k}:{name}"]').get_attribute('aria-selected')=='true')
        # MCP playground input validation and trust handling
        page.locator('[data-page="mcpplay"]').click()
        page.locator('#playArgs').fill('{bad-json')
        page.locator('[data-feature-action="play-mcp"]').click()
        check('MCP rejects malformed JSON','参数必须是 JSON' in page.locator('#playResult').inner_text())
        page.locator('#playArgs').fill('{"reference":"DEMO-001"}')
        page.locator('[data-feature-action="play-mcp"]').click()
        check('MCP allow mock', '"decision": "ALLOW"' in page.locator('#playResult').inner_text())
        page.locator('#playIdentity').select_option('unknown-client')
        page.locator('[data-feature-action="play-mcp"]').click()
        check('MCP deny mock', '"decision": "DENY"' in page.locator('#playResult').inner_text())
        # CEL must not use eval / promise executable CEL
        page.locator('[data-page="tools"]').click()
        page.locator('[data-feature-tab="tools:cel"]').click()
        page.locator('[data-feature-action="cel-test"]').click()
        check('CEL fixed simulation only', '"ruleCompiled": false' in page.locator('#celResult').inner_text())
        page.locator('[data-feature-tab="tools:config"]').click()
        check('raw configuration clearly IDP logical model','不是 agentgateway 原生' in page.locator('#pageContent').inner_text())
        page.locator('[data-page="llm"]').click()
        page.screenshot(path=str(PREV/'07_llm_models.png'))
        page.locator('[data-page="mcp"]').click()
        page.screenshot(path=str(PREV/'08_mcp_servers.png'))
        page.locator('[data-page="catalog"]').click()
        page.screenshot(path=str(PREV/'09_api_onboarding.png'))
        page.locator('[data-page="overview"]').click()
        page.screenshot(path=str(PREV/'10_unified_dashboard.png'))
        check('no uncaught JS errors',len(errors)==0)
        browser.close()
    return checks
if __name__=='__main__':
    results=test()
    print(f'PASS {sum(v for _,v in results)}/{len(results)} checks')
    for name,ok in results:print(('PASS' if ok else 'FAIL'),name)
