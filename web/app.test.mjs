import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));

function startApp(storage, hash = '', fetchImpl = async () => { throw new Error('No API in static preview'); }) {
  const elements = new Map();
  const element = (selector) => {
    if (!elements.has(selector)) elements.set(selector, {
      textContent: '', innerHTML: '', hidden: false, value: '',
      classList: { add() {}, remove() {}, toggle() {} },
      addEventListener() {}, setAttribute() {}, focus() {}
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
    window: { location: { hash } },
    setInterval() { return 1; },
    setTimeout() { return 1; },
    clearTimeout() {},
    fetch: fetchImpl,
    Headers
  });
  vm.runInContext(source, context);
  context.__elements = elements;
  return context;
}

test('dashboard treats empty collection responses as empty arrays', async () => {
  const responses = {
    'api/overview': {connected_sensors:0,monitored_endpoints:0},
    'api/endpoints': null,
    'api/events?limit=500': {items:null,next_cursor:''},
    'api/alerts': null,
    'api/incidents': null,
    'api/rules': null,
    'api/audit': null,
    'api/scenarios': null
  };
  const context = startApp(new Map(), '#overview', async (path) => ({ok:true,status:200,json:async()=>responses[path]}));
  await vm.runInContext('refreshData()', context);
  const collections = JSON.parse(vm.runInContext('JSON.stringify([state.endpoints,state.events,state.alerts,state.incidents,state.rules,state.audit,state.scenarios])', context));
  assert.deepEqual(collections, [[],[],[],[],[],[],[]]);
});

test('live overview metrics exclude replay records while reporting them separately', async () => {
  const context = startApp(new Map());
  vm.runInContext(`
    state.staticDemo = true;
    state.demo = {scenarios:[],rules:[]};
    state.overview = {monitored_endpoints:1,connected_sensors:0};
    state.events = [{id:'LIVE-E1',host_id:'live-host'},{id:'SIM-E1',host_id:'lab-host',simulation_run_id:'SIM-1'}];
    state.alerts = [
      {id:'LIVE-A1',title:'Live finding',status:'open',created_at:'2026-01-01T00:00:00Z'},
      {id:'SIM-A1',title:'Replay finding',status:'open',created_at:'2026-01-01T00:00:00Z',simulation_run_id:'SIM-1'}
    ];
    state.incidents = [
      {id:'LIVE-I1',status:'open'},
      {id:'SIM-I1',status:'open',simulation_run_id:'SIM-1'}
    ];
  `, context);
  const summary = JSON.parse(await vm.runInContext(`demoAPI('api/overview').then(JSON.stringify)`, context));
  assert.equal(summary.live_events, 1);
  assert.equal(summary.simulation_events, 1);
  assert.equal(summary.live_alerts, 1);
  assert.equal(summary.simulation_alerts, 1);
  assert.equal(summary.live_incidents, 1);
  assert.equal(summary.simulation_incidents, 1);
  assert.equal(summary.open_incidents, 1);
  const overview = vm.runInContext('renderOverview()', context);
  assert.match(overview, /1 LIVE/);
  assert.match(overview, /Live finding/);
  assert.doesNotMatch(overview, /Replay finding/);
  vm.runInContext(`updateNavigationCounts(buildEndpoints(state.events),state.alerts,state.incidents)`, context);
  assert.equal(context.__elements.get('#fleet-count').textContent, 1);
  assert.equal(context.__elements.get('#alert-count').textContent, 1);
  assert.equal(context.__elements.get('#incident-count').textContent, 1);
  const detections = vm.runInContext('renderDetections()', context);
  assert.match(detections, /SIM SIM-1/);
});

test('shared page links open the requested dashboard view', () => {
  const context = startApp(new Map(), '#range');
  assert.equal(vm.runInContext('state.view', context), 'range');
  const unknown = startApp(new Map(), '#not-a-view');
  assert.equal(vm.runInContext('state.view', unknown), 'overview');
});

test('rulebook exposes a local Sigma test workspace and labels its Pages boundary', () => {
  const context = startApp(new Map());
  vm.runInContext('state.staticDemo=false; state.rules=[]', context);
  const local = vm.runInContext('renderRules()', context);
  assert.match(local, /Sigma rule workspace/);
  assert.match(local, /data-action="test-sigma"/);
  assert.match(local, /CommandLine\|contains/);
  assert.match(local, /does not add the rule to live ingestion/);
  vm.runInContext('state.staticDemo=true', context);
  const hosted = vm.runInContext('renderRules()', context);
  assert.match(hosted, /LOCAL SERVICE REQUIRED/);
  assert.doesNotMatch(hosted, /data-action="test-sigma"/);
});

test('rulebook identifies bundled Sigma rules and does not invent a confidence score', () => {
  const context = startApp(new Map());
  vm.runInContext(`state.rules=[{
    id:'SEN-SIGMA-PUBLIC-001',sigma_id:'7b0cbd19-cc70-4a9b-b6d1-87c51756a422',kind:'sigma',
    title:'Process execution from a public user directory',description:'Bundled test rule',severity:'medium',
    confidence:0,technique:'T1204.002',field:'image',contains:'\\\\users\\\\public\\\\',
    false_positive:'Approved support tools',revision:1,enabled:true
  }]`, context);
  const rulebook = vm.runInContext('renderRules()', context);
  assert.match(rulebook, /SEN-SIGMA-PUBLIC-001/);
  assert.match(rulebook, /SIGMA 7b0cbd19-cc70-4a9b-b6d1-87c51756a422/);
  assert.match(rulebook, /NOT SCORED/);
  assert.match(rulebook, /run through authenticated ingest/);
});

test('local token entry validates against the service without a blocked browser prompt', () => {
  assert.doesNotMatch(source, /\bprompt\s*\(/);
  assert.match(source, /data-action="test-sigma"/);
  assert.match(source, /api\('api\/overview'/);
  assert.match(source, /aria-expanded/);
});

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

test('simulation archive import adds records and reports without replacing existing browser data', () => {
  const storage = new Map();
  const context = startApp(storage);
  vm.runInContext(`Object.assign(state,{
    staticDemo:true,
    events:[{id:'EXISTING-E1',simulation_run_id:'SIM-OLD'}],
    alerts:[{id:'EXISTING-A1',simulation_run_id:'SIM-OLD'}],
    incidents:[],audit:[{action:'simulation.reset',run_id:'SIM-OLD'}],
    runHistory:[{run_id:'SIM-OLD',scenario_id:'S01',success:true}]
  })`, context);
  assert.throws(() => vm.runInContext(`importSimulationArchive({format:'sentinel-simulation-archive',schema_version:'1.0',simulation_only:true,events:[{id:'LIVE-E1'}]})`, context), /simulation identifiers/);
  const result = vm.runInContext(`importSimulationArchive({
    format:'sentinel-simulation-archive',schema_version:'1.0',simulation_only:true,
    events:[{id:'NEW-E1',simulation_run_id:'SIM-NEW'}],
    alerts:[{id:'NEW-A1',simulation_run_id:'SIM-NEW'}],
    incidents:[{id:'NEW-I1',simulation_run_id:'SIM-NEW'}],
    audit:[{action:'event.ingested',event_id:'NEW-E1'},{action:'event.ingested',event_id:'UNRELATED-LIVE'}],
    completed_runs:[{run_id:'SIM-NEW',scenario_id:'S02',success:true}]
  })`, context);
  assert.deepEqual(JSON.parse(JSON.stringify(result)), {events:1,alerts:1,incidents:1,reports:1});
  const state = JSON.parse(vm.runInContext(`JSON.stringify({events:state.events,alerts:state.alerts,incidents:state.incidents,audit:state.audit,runHistory:state.runHistory})`, context));
  assert.deepEqual(state.events.map((event) => event.id), ['EXISTING-E1','NEW-E1']);
  assert.deepEqual(state.alerts.map((alert) => alert.id), ['EXISTING-A1','NEW-A1']);
  assert.deepEqual(state.incidents.map((incident) => incident.id), ['NEW-I1']);
  assert.equal(state.audit.some((entry) => entry.event_id === 'UNRELATED-LIVE'), false);
  assert.equal(state.runHistory.length, 2);
  assert.ok(storage.has('sentinel-static-demo-v1'));
  const duplicate = vm.runInContext(`importSimulationArchive({
    format:'sentinel-simulation-archive',schema_version:'1.0',simulation_only:true,
    events:[{id:'NEW-E1',simulation_run_id:'SIM-NEW'}],
    alerts:[{id:'NEW-A1',simulation_run_id:'SIM-NEW'}],
    incidents:[{id:'NEW-I1',simulation_run_id:'SIM-NEW'}],
    audit:[{action:'event.ingested',event_id:'NEW-E1'}],
    completed_runs:[{run_id:'SIM-NEW',scenario_id:'S02',success:true}]
  })`, context);
  assert.deepEqual(JSON.parse(JSON.stringify(duplicate)), {events:0,alerts:0,incidents:0,reports:0});
});

test('simulation archive restores a paused replay without starting it', () => {
  const context = startApp(new Map());
  vm.runInContext(`Object.assign(state,{
    staticDemo:true,
    scenarios:[{id:'S01',events:[{id:'E1'},{id:'E2'}]}],
    events:[],alerts:[],incidents:[],audit:[],runHistory:[]
  })`, context);
  vm.runInContext(`importSimulationArchive({
    format:'sentinel-simulation-archive',schema_version:'1.0',simulation_only:true,
    active_run:{run_id:'SIM-PAUSED',scenario_id:'S01',index:1,cursor:1,playing:true,report:null},
    events:[{id:'SIM-PAUSED-E1',simulation_run_id:'SIM-PAUSED'}],alerts:[],incidents:[],completed_runs:[],audit:[]
  })`, context);
  const restored = JSON.parse(vm.runInContext(`JSON.stringify({id:state.run.id,index:state.run.index,cursor:state.run.cursor,playing:state.run.playing,events:state.run.events.map(event=>event.id)})`, context));
  assert.deepEqual(restored, {id:'SIM-PAUSED',index:1,cursor:1,playing:false,events:['SIM-PAUSED-E1']});
});

test('failed archive persistence rolls back imported state and preserves the saved bytes', () => {
  class QuotaMap extends Map {
    failWrites = false;
    set(key, value) {
      if (this.failWrites) throw new Error('Quota exceeded');
      return super.set(key, value);
    }
  }
  const storage = new QuotaMap();
  const context = startApp(storage);
  vm.runInContext(`Object.assign(state,{staticDemo:true,events:[{id:'OLD-E1',simulation_run_id:'SIM-OLD'}],alerts:[],incidents:[],audit:[],runHistory:[]})`, context);
  const original = JSON.stringify({existing:'saved bytes'});
  storage.set('sentinel-static-demo-v1', original);
  storage.failWrites = true;
  assert.throws(() => vm.runInContext(`importSimulationArchive({
    format:'sentinel-simulation-archive',schema_version:'1.0',simulation_only:true,
    events:[{id:'NEW-E1',simulation_run_id:'SIM-NEW'}],alerts:[],incidents:[],completed_runs:[],audit:[]
  })`, context), /prior records remain in place/);
  assert.equal(storage.get('sentinel-static-demo-v1'), original);
  assert.deepEqual(JSON.parse(vm.runInContext('JSON.stringify(state.events.map(event=>event.id))', context)), ['OLD-E1']);
});

test('unreadable saved browser data is left in place for recovery', () => {
  const original = '{not valid JSON';
  const storage = new Map([['sentinel-static-demo-v1', original]]);
  const context = startApp(storage);
  vm.runInContext('restoreDemo()', context);
  assert.equal(storage.get('sentinel-static-demo-v1'), original);
});

test('browser replay evaluator meets every Go-exported scenario assertion', () => {
  const exported = execFileSync('go', ['run', './cmd/export-demo'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      GOMODCACHE: process.env.GOMODCACHE || '/tmp/sentinel-gomodcache',
      GOCACHE: process.env.GOCACHE || '/tmp/sentinel-go-cache'
    }
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
  assert.equal(scenarios.length, 7);
  for (const scenario of scenarios) {
    assert.deepEqual(scenario.actual.sort(), [...(scenario.expected||[])].sort(), `${scenario.id} browser detection assertions`);
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

test('a replay fails when it produces an unexpected alert', () => {
  assert.equal(vm.runInContext(`isRunSuccessful([],[])`, startApp(new Map())), true);
  assert.equal(vm.runInContext(`isRunSuccessful([],['SEN-EXEC-001'])`, startApp(new Map())), false);
  assert.equal(vm.runInContext(`isRunSuccessful(['SEN-EXEC-001'],[])`, startApp(new Map())), false);
});
