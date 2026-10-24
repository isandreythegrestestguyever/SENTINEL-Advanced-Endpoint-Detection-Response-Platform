const $ = (selector) => document.querySelector(selector);
const state = { staticDemo: false, demo: null, events: [], alerts: [], incidents: [] };
const token = () => localStorage.getItem('sentinel-token') || '';

async function api(path, options = {}) {
  if (state.staticDemo) return demoAPI(path, options);
  try {
    const response = await fetch(path, options);
    if (!response.ok) throw new Error(await response.text());
    return await response.json();
  } catch (error) {
    // GitHub Pages cannot host the Go API. Fall back to a clearly labeled browser-only replay.
    if (!path.startsWith('api/')) throw error;
    state.staticDemo = true;
    state.demo = await fetch('demo-data.json').then((response) => {
      if (!response.ok) throw new Error('Static replay data is unavailable.');
      return response.json();
    });
    $('.live').innerHTML = '<i></i> STATIC BROWSER DEMO';
    $('#tokenBtn').hidden = true;
    return demoAPI(path, options);
  }
}

function demoAPI(path, options) {
  if (path === 'api/scenarios') return Promise.resolve(state.demo.scenarios);
  if (path === 'api/rules') return Promise.resolve(state.demo.rules);
  if (path === 'api/health') return Promise.resolve({ status: 'ok', mode: 'static-browser-demo' });
  if (path === 'api/events') return Promise.resolve(state.events);
  if (path === 'api/alerts') return Promise.resolve(state.alerts);
  if (path === 'api/incidents') return Promise.resolve(state.incidents);
  if (path === 'api/audit') return Promise.resolve([]);
  if (path === 'api/overview') return Promise.resolve({
    monitored_endpoints: 0, connected_sensors: 0, open_incidents: 0,
    events: state.events.length, alerts: state.alerts.length,
    mode: 'STATIC BROWSER DEMO · SESSION DATA ONLY'
  });
  if (path === 'api/simulate' && options.method === 'POST') {
    const request = JSON.parse(options.body);
    const scenario = state.demo.scenarios.find((item) => item.id === request.scenario_id);
    if (!scenario) throw new Error('Unknown scenario.');
    const runID = `STATIC-${Date.now()}`;
    const alerts = [];
    const events = scenario.events.map((event) => ({ ...event, id: `${runID}-${event.id}`, simulation_run_id: runID }));
    for (const event of events) {
      state.events.push(event);
      for (const rule of state.demo.rules) {
        if (!rule.enabled) continue;
        const value = event[rule.field] || '';
        if (value.toLowerCase().includes(rule.contains.toLowerCase())) {
          alerts.push({
            id: `ALT-${event.id}-${rule.id}`, rule_id: rule.id, title: rule.title,
            severity: rule.severity, confidence: rule.confidence, technique: rule.technique,
            host_id: event.host_id, hostname: event.hostname, event_ids: [event.id],
            evidence: `${rule.field} matched ${rule.id} containing "${rule.contains}"`,
            created_at: new Date().toISOString(), simulation_run_id: runID, status: 'open'
          });
        }
      }
    }
    state.alerts.push(...alerts);
    const matched = new Set(alerts.map((alert) => alert.rule_id));
    const detected = scenario.expected_rule_ids.filter((id) => matched.has(id));
    const missed = scenario.expected_rule_ids.filter((id) => !matched.has(id));
    const unexpected = [...new Set(alerts.map((alert) => alert.rule_id))].filter((id) => !scenario.expected_rule_ids.includes(id));
    return Promise.resolve({
      scenario: scenario.name, scenario_id: scenario.id, scenario_version: '1.0',
      dataset_version: '1.0', rule_set_version: '1', simulation_seed: 'deterministic-fixture-v1',
      run_id: runID, event_count: events.length, expected_alerts: scenario.expected_rule_ids,
      detected, missed, unexpected, success: missed.length === 0,
      precision: detected.length + unexpected.length ? detected.length / (detected.length + unexpected.length) : null,
      recall: scenario.expected_rule_ids.length ? detected.length / scenario.expected_rule_ids.length : null,
      errors: [], alert_count: alerts.length
    });
  }
  return Promise.reject(new Error('This endpoint is unavailable in the static browser demo.'));
}

async function refresh() {
  try {
    const [overview, alerts, rules] = await Promise.all([api('api/overview'), api('api/alerts'), api('api/rules')]);
    $('#endpoints').textContent = overview.monitored_endpoints;
    $('#sensors').textContent = overview.connected_sensors;
    $('#incidents').textContent = overview.open_incidents;
    $('#events').textContent = overview.events;
    $('#mode').textContent = overview.mode;
    $('#alerts').innerHTML = alerts.length ? alerts.slice().reverse().slice(0, 30).map((alert) => `<tr><td><span class="severity ${esc(alert.severity)}">${esc(alert.severity)}</span></td><td><b>${esc(alert.title)}</b><br><small>${esc(alert.rule_id)} · ${esc(alert.technique || '—')}</small></td><td>${esc(alert.hostname)}</td><td><span class="simulation">${state.staticDemo ? 'STATIC DEMO' : 'SIM'} · ${esc(alert.simulation_run_id)}</span></td><td>${esc(alert.status)}</td></tr>`).join('') : '<tr><td colspan="5" class="empty">No alerts. Run a scenario in Sentinel Range.</td></tr>';
    $('#rulesList').innerHTML = rules.map((rule) => `<div class="rule"><b>${esc(rule.title)}</b><code>${esc(rule.id)}</code><small>${esc(rule.description)} · ${esc(rule.severity)} · ${esc(rule.technique)}</small></div>`).join('');
  } catch (error) { $('#mode').textContent = 'API unavailable'; console.error(error); }
}

async function loadScenarios() {
  try {
    const scenarios = await api('api/scenarios');
    $('#scenario').innerHTML = scenarios.map((scenario) => `<option value="${esc(scenario.id)}">${esc(scenario.id)} — ${esc(scenario.name)}</option>`).join('');
  } catch (error) { console.error(error); }
}

$('#tokenBtn').onclick = () => {
  const value = prompt('Paste the analyst token printed when the local server started. It stays in this browser.');
  if (value) { localStorage.setItem('sentinel-token', value.trim()); $('#tokenBtn').textContent = 'TOKEN SAVED'; }
};
$('#run').onclick = async () => {
  if (!state.staticDemo && !token()) { alert('Set analyst token first. Find it in the server terminal.'); return; }
  $('#run').disabled = true;
  $('#result').textContent = 'Replaying normalized events through the detection rules…';
  try {
    const report = await api('api/simulate', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token()}` },
      body: JSON.stringify({ scenario_id: $('#scenario').value })
    });
    $('#result').innerHTML = `<b class="${report.success ? 'ok' : 'bad'}">${report.success ? 'SCENARIO PASSED' : 'SCENARIO FAILED'}</b><br>${report.event_count} events · ${report.detected.length}/${report.expected_alerts.length} expected rules detected<br>Recall: ${report.recall === null ? 'undefined' : Math.round(report.recall * 100) + '%'} · Precision: ${report.precision === null ? 'undefined' : Math.round(report.precision * 100) + '%'}<br>Run ${esc(report.run_id)}<br>${report.missed.length ? 'Missed: ' + esc(report.missed.join(', ')) : 'All mandatory assertions met.'}<br><button id="report">EXPORT JSON REPORT</button>`;
    $('#report').onclick = () => download(report);
    await refresh();
  } catch (error) { $('#result').innerHTML = `<span class="bad">${esc(error.message)}</span>`; }
  finally { $('#run').disabled = false; }
};
$('#refresh').onclick = refresh;
function esc(value) { return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]); }
function download(report) {
  const anchor = document.createElement('a');
  anchor.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  anchor.download = `sentinel-${report.run_id}.json`; anchor.click(); URL.revokeObjectURL(anchor.href);
}
loadScenarios();
refresh();
setInterval(refresh, 8000);
