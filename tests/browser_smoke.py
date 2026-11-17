"""Browser smoke test. Requires playwright only for development, installed separately."""
import json,os,pathlib,subprocess,time,urllib.request
from playwright.sync_api import sync_playwright
root=pathlib.Path(__file__).resolve().parents[1]
base=os.environ.get('AETHER_TEST_URL','http://127.0.0.1:8123').rstrip('/')
p=None if os.environ.get('AETHER_TEST_URL') else subprocess.Popen(['python','server.py'],cwd=root,env={**os.environ,'PORT':'8123'},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
 for _ in range(50):
  try:urllib.request.urlopen(base+'/health',timeout=10);break
  except Exception:time.sleep(.1)
 with sync_playwright() as pw:
  browser=pw.chromium.launch(executable_path='/usr/bin/google-chrome',headless=True,args=['--no-sandbox'])
  context=browser.new_context(viewport={'width':1512,'height':1100},device_scale_factor=1)
  page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
  page.goto(base);page.wait_for_selector('#stats .stat-value');page.wait_for_timeout(2200);page.screenshot(path='/downloads/aether-dashboard-desktop.png',full_page=True)
  page.locator('[data-intent="Prioritize video and block p2p"]').click();page.locator('#propose').click();page.wait_for_selector('#approve');page.locator('#approve').click();page.wait_for_function('() => document.querySelector("#revision").textContent.includes("Revision 1")');
  page.locator('button.nav[data-tab="policies"]').click();assert page.locator('#policy-list').inner_text().count('Approved')==2
  page.locator('button.nav[data-tab="overview"]').click();page.locator('[data-link="s1-s3"]').click();page.locator('#toggle-link').click();page.locator('#confirm button[value="ok"]').click();page.wait_for_function('() => document.querySelector("#revision").textContent.includes("Revision 2")');
  page.locator('button.nav[data-tab="flows"]').click();assert page.locator('#flow-table tr').count()==8
  page.screenshot(path='/downloads/aether-flow-explorer.png',full_page=True)
  page.locator('button.nav[data-tab="history"]').click();page.locator('[data-restore]').last.click();page.locator('#confirm button[value="ok"]').click();page.wait_for_function('() => document.querySelector("#revision").textContent.includes("Revision 3")');
  page.locator('button.nav[data-tab="overview"]').click();page.locator('#intent').fill('block all traffic');page.locator('#propose').click();page.wait_for_selector('#error:not(.hidden)');assert 'Safety' in page.locator('#error').inner_text()
  assert not errors,errors
  # Different browser context gets an independent twin at revision zero.
  other=browser.new_context();pg=other.new_page();pg.goto(base);pg.wait_for_selector('#stats .stat-value');assert 'Revision 0' in pg.locator('#revision').inner_text();other.close()
  mobile=browser.new_context(viewport={'width':390,'height':844},is_mobile=True,device_scale_factor=1);mp=mobile.new_page();mp.goto(base);mp.wait_for_selector('#stats .stat-value');assert mp.evaluate('document.documentElement.scrollWidth <= window.innerWidth');mp.screenshot(path='/downloads/aether-dashboard-mobile.png',full_page=True);mobile.close()
  print(json.dumps({'base_url':base,'browser':'Chromium','checks':['dashboard render','policy preview/approval','registry update','link fault confirmation','flow explorer','snapshot rollback','unsafe rejection','visitor isolation','mobile no-overflow'],'page_errors':errors,'desktop_screenshot':'/downloads/aether-dashboard-desktop.png','mobile_screenshot':'/downloads/aether-dashboard-mobile.png'},indent=2));browser.close()
finally:
 if p:p.terminate();p.wait(timeout=5)
