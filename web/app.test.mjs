import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('./app.js', import.meta.url), 'utf8');

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
    persistDemo();
  `, firstPage);

  const reloadedPage = startApp(storage);
  vm.runInContext('restoreDemo()', reloadedPage);
  const restored = JSON.parse(vm.runInContext(`JSON.stringify({
    events: state.events,
    alerts: state.alerts,
    incidents: state.incidents,
    audit: state.audit,
    run: state.run
  })`, reloadedPage));
  assert.equal(restored.events[0].simulation_run_id, 'SIM-1');
  assert.equal(restored.alerts[0].id, 'ALT-1');
  assert.equal(restored.incidents[0].id, 'INC-1');
  assert.equal(restored.audit[0].action, 'event.ingested');
  assert.equal(restored.run.report.success, true);
  assert.equal(restored.run.playing, false);
});
