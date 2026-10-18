// Renders viewer/report-template.html with synthetic data in a minimal fake DOM (no dependencies) and checks what the
// page shows: KPI populations, typical-time statistics, reserved names, the MDM settings table and the CSV export.
// Run: node tests/Test-Viewer.js   - expect "0 failure(s)".
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'viewer', 'report-template.html'), 'utf8');
const code = html.split('<script>')[1].split('</script>')[0];
let fail = 0;
function check(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) fail++; }

// ------------------------------------------------------------------ fake DOM: just what the viewer uses
class Text { constructor(t) { this.nodeType = 3; this.data = String(t); this.parentNode = null; } get textContent() { return this.data; } }
class El {
  constructor(tag) {
    this.nodeType = 1; this.tagName = String(tag).toUpperCase(); this.childNodes = []; this.parentNode = null; this.attrs = {};
    this.listeners = {}; this.style = {}; this.dataset = {}; this.className = ''; this.value = ''; this.clientWidth = 1000; this.offsetWidth = 200; this.offsetHeight = 60;
    const self = this;
    this.classList = { add(c) { self.className = (self.className + ' ' + c).trim(); }, remove(c) { self.className = self.className.split(' ').filter(x => x !== c).join(' '); }, contains(c) { return self.className.split(' ').includes(c); } };
  }
  append(...kids) { for (let k of kids) { if (!(k instanceof El || k instanceof Text)) k = new Text(k); if (k.parentNode) k.parentNode._remove(k); k.parentNode = this; this.childNodes.push(k); } }
  _remove(k) { const i = this.childNodes.indexOf(k); if (i >= 0) this.childNodes.splice(i, 1); }
  replaceChildren(...kids) { this.childNodes.forEach(c => { c.parentNode = null; }); this.childNodes = []; this.append(...kids); }
  remove() { if (this.parentNode) this.parentNode._remove(this); this.parentNode = null; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  fire(t) { const e = { preventDefault() {}, key: 'Enter' }; (this.listeners[t] || []).forEach(f => f(e)); if (typeof this['on' + t] === 'function') this['on' + t](e); }
  click() { this.fire('click'); }
  get textContent() { return this.childNodes.map(c => c.textContent).join(''); }
  set textContent(v) { this.replaceChildren(new Text(v)); }
  get children() { return this.childNodes.filter(c => c.nodeType === 1); }
  getBoundingClientRect() { return { left: 0, top: 0, width: 1000, height: 300 }; }
  getContext() { return { font: '', measureText: s => ({ width: String(s).length * 6 }) }; }
  scrollIntoView() {} querySelectorAll() { return []; } querySelector() { return null; }
  all(pred, out = []) { for (const c of this.children) { if (pred(c)) out.push(c); c.all(pred, out); } return out; }
}

function render(data) {
  const ids = ['bootview-data', 'content', 'device', 'notices', 'f-range', 'f-type', 'f-view', 'f-wait', 'kpis', 'chart', 'chart-sub', 'legend', 'detail', 'typical', 'table', 'csv', 'foot', 'theme'];
  const byId = {};
  ids.forEach(id => { byId[id] = new El(id === 'f-type' ? 'select' : 'div'); byId[id].id = id; });
  byId['bootview-data'].append(JSON.stringify(data));
  const blobs = [];
  const document = {
    getElementById: id => byId[id] || null,
    createElement: t => new El(t), createElementNS: (ns, t) => new El(t), createTextNode: t => new Text(t),
    body: new El('body'), documentElement: new El('html')
  };
  const sandbox = {
    document, window: { addEventListener() {} }, localStorage: { getItem() { return null; }, setItem() {} },
    URL: { createObjectURL(b) { blobs.push(b); return 'blob:test'; } }, Blob, setTimeout, clearTimeout, console
  };
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  return { $: id => byId[id], blobs };
}
function button(host, text) { return host.all(n => n.tagName === 'BUTTON' && n.textContent.replace('✓ ', '') === text)[0]; }

// ------------------------------------------------------------------ data
const DAY = 86400000, T0 = Date.UTC(2026, 9, 1, 7, 0, 0);
function boot(i, o) {
  const s0 = T0 + i * DAY;
  const b = {
    id: s0, bootStartMs: s0, bootType: 0, phases: [{ key: 'boot', startMs: 0, durMs: 20000 }],
    totals: { readyMs: 20000, readyExclWaitMs: 20000, coreBootMs: 15000, signInToReadyMs: 5000, signInWaitMs: 0 },
    logon: { tasks: [], startupApps: [], shellPhases: [] }, winlogon: [], issues: []
  };
  return Object.assign(b, o || {});
}
const fw = { firmwareMs: 10000, loaderMs: 0 };

console.log('Power-on KPIs never count missing firmware as 0 (review 1, finding 6)');
{
  const r = render({ schema: 3, collectedMs: T0 + 9 * DAY, device: { name: 'PC' }, sources: {}, boots: [
    boot(0, { phases: [{ key: 'firmware', startMs: -10000, durMs: 10000 }, { key: 'boot', startMs: 0, durMs: 20000 }], totals: Object.assign({}, boot(0).totals, { firmwareMs: 10000, loaderMs: 0 }), firmware: fw }),
    boot(1)] });
  const k = r.$('kpis').textContent;
  check('power-on median uses only boots with firmware timing (30 s, not 25 s)', /Median Power-on → ready.*?30\.0 s/.test(k) && !k.includes('25.0 s'));
  check('coverage shown ("1 of 2")', k.includes('1 of 2 boots measured for this view'));
  check('chart says why a boot is missing', r.$('chart-sub').textContent.includes('1 boot without firmware timing omitted'));
  button(r.$('f-view'), 'Windows start → ready').click();
  const k2 = r.$('kpis').textContent;
  check('Windows-only view includes both boots (20 s, 2 of 2)', /20\.0 s/.test(k2) && k2.includes('2 of 2 boots measured'));
}

console.log('Unknown sign-in wait is not shown as wait-excluded (review 1, finding 5)');
{
  const unknown = boot(1, { totals: { readyMs: 60000, readyExclWaitMs: null, coreBootMs: null, signInToReadyMs: 5000, signInWaitMs: null }, phases: [{ key: 'boot', startMs: 0, durMs: 60000 }] });
  const r = render({ schema: 3, device: { name: 'PC' }, sources: {}, boots: [boot(0), unknown] });
  check('excluded while the wait is excluded', r.$('kpis').textContent.includes('1 of 2 boots measured') && r.$('chart-sub').textContent.includes('sign-in screen wait is unknown'));
  button(r.$('f-wait'), 'Include').click();
  check('included when the wait is included', r.$('kpis').textContent.includes('2 of 2 boots measured'));
}

console.log('Reserved names and per-boot statistics (review 1, findings 9 and 10)');
{
  const t = (name, ms, s) => ({ name, startMs: s || 0, endMs: (s || 0) + ms, durMs: ms });
  const reserved = i => boot(i, { logon: { allTasks: t('AllLogonTasks', 5000), tasks: [t('constructor', 100 * (i + 1)), t('__proto__', 200), t('toString', 300), t('hasOwnProperty', 50)], startupApps: [{ name: 'constructor', durMs: 10 }], shellPhases: [] } });
  const mdmA = { sessions: Array.from({ length: 10 }, (_, j) => ({ startMs: j, endMs: j + 1000, durMs: 1000 })), policyCount: 0, policies: [], errors: [], bursts: [], areas: [] };
  const mdmB = { sessions: [{ startMs: 0, endMs: 100000, durMs: 100000 }], policyCount: 0, policies: [], errors: [], bursts: [], areas: [] };
  const repeated = boot(5, { logon: { allTasks: t('AllLogonTasks', 5000), tasks: [t('X', 4000, 0), t('X', 4000, 1), t('X', 4000, 2)], startupApps: [], shellPhases: [] } });
  let r, err = null;
  try {
    r = render({ schema: 3, device: { name: 'PC', mdm: 'Intune' }, sources: {}, boots: [reserved(0), reserved(1), reserved(2), boot(3, { mdm: mdmA }), boot(4, { mdm: mdmB }), repeated] });
  } catch (e) { err = e; }
  check('report renders with tasks named constructor / __proto__ / toString', !err && r.$('detail').textContent.length > 0);
  if (err) console.log('    ' + err.stack.split('\n').slice(0, 2).join(' | '));
  const sel = r && r.$('typical').all(n => n.tagName === 'SELECT')[0];
  if (sel) { sel.value = 'tasks'; sel.onchange(); }
  const typ = r ? r.$('typical').textContent : '';
  check('typical table lists the reserved names', typ.includes('constructor') && typ.includes('__proto__') && typ.includes('toString'));
  const sel2 = r && r.$('typical').all(n => n.tagName === 'SELECT')[0];
  if (sel2) { sel2.value = 'mdm'; sel2.onchange(); }
  const rows = r ? r.$('typical').all(n => n.tagName === 'TR').map(tr => tr.children.map(td => td.textContent)) : [];
  const sync = rows.filter(x => x[0] === 'MDM sync session')[0] || [];
  check('each boot counts once: Boots 2, Runs 11, median of per-boot totals 55 s', sync[1] === '2' && sync[2] === '11' && sync[3] === '55.0 s');
  check('worst is the worst boot (100 s)', sync[5] === '1m 40s');
  // the selected boot (newest) has task X three times in one boot: three runs are not three boots, so no "typical"
  const gantt = r ? r.$('detail').all(n => n.tagName === 'SECTION' && n.textContent.startsWith('Logon tasks'))[0] : null;
  check('three runs in one boot do not make a typical value', gantt && gantt.textContent.includes('X') && !gantt.textContent.includes('typical'));
}

console.log('MDM settings are shown (review 1, finding 11)');
{
  const pol = { t: T0 + 61000, op: 'set', policy: 'ZZFixturePolicy', area: 'Defender', scope: 'device', value: 'ZZValue42' };
  const r = render({ schema: 3, device: { name: 'PC', mdm: 'Intune' }, sources: {}, boots: [boot(0, { mdm: { sessions: [], policyCount: 5, policies: [pol], errors: [], bursts: [], areas: [] } })] });
  const card = r.$('detail').all(n => n.tagName === 'SECTION' && n.textContent.startsWith('Intune policies (MDM)'))[0];
  const txt = card ? card.textContent : '';
  check('setting name, area and value listed', txt.includes('ZZFixturePolicy') && txt.includes('ZZValue42') && txt.includes('Defender'));
  check('stored vs total count shown', txt.includes('first 1 of 5 stored'));
}

console.log('CSV export is spreadsheet-safe (review 1, finding 8)');
{
  const r = render({ schema: 3, collectedMs: T0, device: { name: '-1+2', serial: '\t=1+2', entraDeviceId: 'a\rb', intuneDeviceId: '=HYPERLINK("http://x")' }, sources: {}, boots: [boot(0)] });
  r.$('csv').click();
  check('one CSV produced', r.blobs.length === 1);
  r.blobs[0].text().then(csv => {
    const row = csv.split('\r\n')[1];
    check("leading '-' gets a quote prefix", row.startsWith("'-1+2,"));
    check("leading tab + '=' gets a quote prefix", row.includes(",'\t=1+2,"));
    check('a bare CR is quoted', row.includes(',"a\rb",'));
    check("leading '=' prefixed and inner quotes doubled", row.includes(',"\'=HYPERLINK(""http://x"")",'));
    check('numbers stay numbers', /,20000,/.test(row));
    console.log(`node ${process.version}: ${fail} failure(s)`);
    process.exitCode = fail ? 1 : 0;
  });
}
