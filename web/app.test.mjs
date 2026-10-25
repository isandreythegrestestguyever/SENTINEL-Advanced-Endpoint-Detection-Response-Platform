import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));

function startApp(storage) {
  const elements = new Map();
  const element = (selector) => {
    if (!elements.has(selector)) elements.set(selector, {
      textContent: '', innerHTML: '', hidden: false, value: '',
      classList: { add() {}, remove() {}, toggle() {} }
    });
    return elements.get(selector);
  };
  const context = vm.createContext({
    console,
    localStorage: {
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, String(value)),
      removeItem: (key) => storage.delete(key)
    },
    document: {
      querySelector: element,
      querySelectorAll: () => [],
      addEventListener() {}
    },
    window: { location: { hash: '' } },
    setInterval() { return 1; },
    setTimeout() { return 1; },
    clearTimeout() {},
    fetch: async () => { throw new Error('No API in static preview'); }
  });
  vm.runInContext(source, context);
  return context;
}

test('static replay records and report survive reload in the same browser store', () => {
  const storage = new Map();
  const firstPage = startApp(storage);
  vm.runInContext(`
    state.staticDemo = true;
    state.events = [{id:'SIM-1-E01', simulation_run_id:'SIM-1'}];
    state.alerts = [{id:'ALT-1', simulation_run_id:'SIM-1'}];
    state.incidents = [{id:'INC-1', simulation_run_id:'SIM-1'}];
    state.audit = [{action:'event.ingested'}];
    state.run = {id:'SIM-1', report:{success:true}, playing:false};
    state.runHistory = [{run_id:'SIM-0',scenario_id:'S01',success:true}];
    persistDemo();
  `, firstPage);

  const reloadedPage = startApp(storage);
  vm.runInContext('restoreDemo()', reloadedPage);
  const restored = JSON.parse(vm.runInContext(`JSON.stringify({
    events: state.events,
    alerts: state.alerts,
    incidents: state.incidents,
    audit: state.audit,
    run: state.run,
    runHistory: state.runHistory
  })`, reloadedPage));
  assert.equal(restored.events[0].simulation_run_id, 'SIM-1');
  assert.equal(restored.alerts[0].id, 'ALT-1');
  assert.equal(restored.incidents[0].id, 'INC-1');
  assert.equal(restored.audit[0].action, 'event.ingested');
  assert.equal(restored.run.report.success, true);
  assert.equal(restored.run.playing, false);
  assert.equal(restored.runHistory[0].run_id, 'SIM-0');
});

test('static event history keeps every browser replay record when paged API is requested', async () => {
  const context = startApp(new Map());
  const events = Array.from({length: 700}, (_, index) => ({id:`SIM-1-E${index + 1}`, simulation_run_id:'SIM-1'}));
  vm.runInContext(`state.staticDemo = true; state.events = ${JSON.stringify(events)}`, context);
  const page = await vm.runInContext(`demoAPI('api/events?limit=500')`, context);
  assert.equal(page.items.length, 700);
  assert.equal(page.items[0].id, 'SIM-1-E1');
  assert.equal(page.items[699].id, 'SIM-1-E700');
  assert.equal(page.next_cursor, '');
});

test('process graph connects only observed parent IDs and exposes missing ancestry', () => {
  const context = startApp(new Map());
  const events = [
    {id:'E1',host_id:'host-1',process_id:100,parent_process_id:20,time:'2026-01-01T00:00:00Z',image:'powershell.exe'},
    {id:'E2',host_id:'host-1',process_id:200,parent_process_id:100,time:'2026-01-01T00:00:01Z',image:'child.exe'},
    {id:'E3',host_id:'host-1',process_id:300,parent_process_id:900,time:'2026-01-01T00:00:02Z',image:'orphan.exe'}
  ];
  const summary = vm.runInContext(`(() => {
    const tree = buildProcessTree(${JSON.stringify(events)});
    return {roots:tree.roots.map(node => node.pid),children:tree.nodes.find(node => node.pid === 100).children.map(node => node.pid),unobserved:tree.nodes.filter(node => node.unobservedParent).map(node => [node.pid,node.unobservedParent])};
  })()`, context);
  assert.deepEqual(JSON.parse(JSON.stringify(summary)), {roots:[100,300],children:[200],unobserved:[[100,20],[300,900]]});
  vm.runInContext(`state.events = ${JSON.stringify(events)}; state.alerts = [];`, context);
  const html = vm.runInContext('renderProcesses()', context);
  assert.match(html, /PARENT PID 20 · NOT IN LOADED EVENTS/);
  assert.match(html, /data-process-pid="200"/);
  assert.doesNotMatch(html, /HOST host-1 <span>└─ PARENT PID 20/);
});

test('simulation archive preserves saved runs and excludes live records', async () => {
  const context = startApp(new Map());
  vm.runInContext(`Object.assign(state,{
    staticDemo:true,
    scenarios:[{id:'S01'}],
    events:[{id:'SIM-E1',simulation_run_id:'SIM-1'},{id:'LIVE-E1'}],
    alerts:[{id:'SIM-A1',simulation_run_id:'SIM-1'},{id:'LIVE-A1'}],
    incidents:[{id:'SIM-I1',simulation_run_id:'SIM-1'},{id:'LIVE-I1'}],
    audit:[{action:'event.ingested',event_id:'SIM-E1'},{action:'event.ingested',event_id:'LIVE-E1'},{action:'simulation.reset',run_id:'SIM-1'}],
    runHistory:[{run_id:'SIM-OLD',scenario_id:'S01',success:true}],
    run:{id:'SIM-1',scenario:{id:'S01'},index:1,cursor:1,playing:false}
  })`, context);
  const archive = await vm.runInContext('buildSimulationArchive()', context);
  assert.equal(archive.format, 'sentinel-simulation-archive');
  assert.equal(archive.simulation_only, true);
  assert.deepEqual(JSON.parse(JSON.stringify(archive.events.map((event) => event.id))), ['SIM-E1']);
  assert.deepEqual(JSON.parse(JSON.stringify(archive.alerts.map((alert) => alert.id))), ['SIM-A1']);
  assert.deepEqual(JSON.parse(JSON.stringify(archive.incidents.map((incident) => incident.id))), ['SIM-I1']);
  assert.deepEqual(JSON.parse(JSON.stringify(archive.audit.map((entry) => entry.action))), ['event.ingested','simulation.reset']);
  assert.equal(archive.completed_runs[0].run_id, 'SIM-OLD');
  assert.equal(archive.active_run.run_id, 'SIM-1');
});

test('browser replay evaluator meets every Go-exported scenario assertion', () => {
  const exported = execFileSync('go', ['run', './cmd/export-demo'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: { ...process.env, GOCACHE: process.env.GOCACHE || join(tmpdir(), 'sentinel-go-cache') }
  });
  const fixtureData = JSON.parse(exported);
  const context = startApp(new Map());
  vm.runInContext(`state.demo = ${JSON.stringify(fixtureData)}`, context);
  const result = vm.runInContext(`JSON.stringify(state.demo.scenarios.map((scenario) => {
    const previous = [];
    const alerts = [];
    for (const event of scenario.events) {
      event.simulation_run_id = 'browser-test-' + scenario.id;
      for (const rule of state.demo.rules) {
        const finding = evaluateDemoRule(rule, event, previous);
        if (finding) alerts.push(finding.rule.id);
      }
      previous.push(event);
    }
    return {id: scenario.id, expected: scenario.expected_rule_ids, actual: [...new Set(alerts)]};
  }))`, context);
  const scenarios = JSON.parse(result);
  assert.equal(scenarios.length, 6);
  for (const scenario of scenarios) {
    assert.deepEqual(scenario.actual.sort(), [...scenario.expected].sort(), `${scenario.id} browser detection assertions`);
  }
});

test('simulation report Markdown keeps evidence and undefined denominators explicit', () => {
  const context = startApp(new Map());
  const report = {
    scenario: 'Safe fixture', scenario_id: 'S01', run_id: 'SIM-1',
    scenario_version: '1.0', dataset_version: '1.0', rule_set_version: '1',
    simulation_seed: 'fixture-v1', event_count: 1, success: false,
    recall: null, precision: 0, expected_alerts: ['SEN-EXEC-001'],
    detected: [], missed: ['SEN-EXEC-001'], unexpected: [],
    ground_truth_techniques: ['T1059'], detected_techniques: [],
    alerts: [{title:'Example alert', rule_id:'SEN-EXEC-001', severity:'high', technique:'T1059', evidence:'command line matched', event_ids:['E1']}],
    processing_errors: []
  };
  const markdown = vm.runInContext(`formatReportMarkdown(${JSON.stringify(report)})`, context);
  assert.match(markdown, /Recall: undefined/);
  assert.match(markdown, /Missed: SEN-EXEC-001/);
  assert.match(markdown, /Scenario ground truth: T1059/);
  assert.match(markdown, /Event IDs: E1/);
  assert.match(markdown, /do not estimate real-world detection quality/);
});
