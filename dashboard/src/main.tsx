import React, { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import ReviewWorkspace from "./ReviewWorkspace";
import EvaluationInsights from "./EvaluationInsights";
import GroundingEvidence from "./GroundingEvidence";
import {matchesEvidence, evidenceCsv} from "./evaluation";

type Label = { trust: string; confidentiality: string; source_count: number; sink_count: number };
type Trace = { policy_digest: string; effect_count: number; steps: { index: number; op: string; inputs: Label[]; output?: Label; decision?: {allowed: boolean; reason: string; rule: string} }[] };
type Event = { event: { action: string; rule: string; reason?: string; duration_ms?: number; trace?: Trace | string }; digest: string };
type Attack = { id: string; payload: string; category: string; goal: string };
type Policy = { text: string; digest: string; history: { revision: number; digest: string }[] };
type ArenaResult = {
  level: number; defense: string; agent: string; attack_id: string; success: boolean;
  input_payload: string; evidence_steps: string[]; limitations: string; legacy_case: boolean;
  outcome: string; category: string; goal: string; external_effect_count: number; payload_sha256: string; oracle: {kind: string; destination: string; content: string};
  explanation: string; decisions: string[]; output: string;
  attempted_action: {kind: string; destination: string; content: string};
  effects: {kind: string; destination: string; content: string}[]; trace?: Trace;
};
const outcomeNames: Record<string, string> = {attack_succeeded: "Scripted action reproduced", blocked: "Blocked before execution", action_not_planned: "Action excluded by fixed program", goal_not_observed: "Objective not observed"};
const levelNames = ["0 · Vulnerable", "1 · Detector", "2 · Detector + sanitizer", "3 · Full IFC"];
type ModelRun = {defense: string; status: string; attack_success: boolean; utility_success: boolean;
  model_calls: number; duration_ms: number; answer: string; answer_text?: string; model_protocol_errors?:number; model_recoveries?:string[]; error_code?: string; outcome_details?: Record<string,unknown>; state_changes?: Record<string,unknown>;
  events: {step: number; kind: string; message: string; details: Record<string, unknown>}[];
  effects: {tool: string; recipient: string; body: string}[]};
type EvaluationRecord = {case_id?: string; scenario_id?: string; task?: string; case: string; email: string; payload_sha256: string; round?: number; run: ModelRun};

type SavedSetup = {recover_model_errors?: boolean; grounding?: string; kind: "agent" | "campaign" | "suite"; title?: string; defense: string; email: string; adaptive_rounds: number; max_turns: number; scenario_id: string; partition?: string; variation?: number; attack_goal?: string; attack_channel?: string; attack_strategy?: string; selected_defenses?: string[]};
type LabJob = {id: string; title?: string; kind?: string; spec?: SavedSetup; status: string; created: number; result?: {model_calls?: number;
  dataset_digest?: string; scenario_results?: {id: string; name: string; summary: {defense: string; attack_successes: number; attack_trials: number; benign_successes: number; benign_trials: number}[]}[];
  spec?: SavedSetup; model?: string; scenario?: {name: string; task: string}; policy_digest?: string; attacker_attempts?: {defense: string; round: number; accepted: boolean; response: string}[];
  active_scenario?: string; completed_runs?: number; attacker_errors?: number; error_code?: string; limits?: string;
  summary?: {defense: string; attack_trials: number; attack_successes: number;
    p50_ms?: number; p95_ms?: number; model_calls?: number; asr_interval?: number[]; static_successes?: number; adaptive_successes?: number; invalid_attack_runs: number; benign_trials: number; benign_successes: number; conclusive: boolean}[];
  records?: EvaluationRecord[]}};
type LabConfig = {enabled: boolean; provider: string; model: string; task: string;
  scenarios: {workflow?: boolean; id: string; name: string; task: string; email: string; attacks: Record<string,string>}[]; strategies: Record<string,string>; tools: string;
  attack_email: string; benign_email: string; defenses: string[]};


function actionPath(run: ModelRun): string {
  const actions = run.events.filter(e => e.kind === "model-action").map(e => {
    const action = e.details.action;
    return typeof action === "object" && action !== null && "action" in action ? String(action.action) : "validated action";
  });
  if (actions.length) return actions.join(" → ");
  if (run.status === "blocked") return "detector → blocked";
  const stages = run.events.filter(e => ["planner", "quarantine", "grounding", "policy", "error"].includes(e.kind) || (e.kind === "tool-result" && typeof e.details.tool === "string")).map(e => e.kind === "tool-result" ? String(e.details.tool) : e.kind);
  return [...new Set(stages)].join(" → ") || run.status;
}

function groupCases(records: EvaluationRecord[]) {
  const groups = new Map<string, EvaluationRecord[]>();
  for (const record of records) {
    const id = `${record.scenario_id || "custom"}:${record.case}:${record.round || 0}:${record.payload_sha256}`;
    groups.set(id, [...(groups.get(id) || []), record]);
  }
  return [...groups.entries()];
}

function EvaluationCase({records, title}: {records: EvaluationRecord[]; title: string}) {
  const [defense, setDefense] = useState("full-ifc");
  const selected = records.find(r => r.run.defense === defense) || records[0];
  const record = records[0];
  return <article className="arena-evidence evaluation-case">
    <h3>{title} · {record.case === "benign" ? "Normal task" : record.case === "static" ? "Attack case" : record.case} {record.round || ""}</h3>
    {record.task && <p><strong>Trusted objective:</strong> {record.task}</p>}
    {record.case_id && <p><strong>Recorded case:</strong> {record.case_id}</p>}
    <p><strong>Unique input:</strong> <code>{record.payload_sha256.slice(0,16)}</code> · {records.length} defense executions</p>
    <pre className="case-input">{record.email}</pre>
    <div className="table-scroll"><table><thead><tr><th>Defense</th><th>Observed path</th><th>Security violation</th><th>Task completed</th><th>Duration</th></tr></thead><tbody>{records.map(r => <tr key={r.run.defense}><td>{r.run.defense}</td><td>{actionPath(r.run)}</td><td>{r.run.attack_success ? (["error","budget-exhausted"].includes(r.run.status) ? "Observed · incomplete run" : "Observed") : ["error","budget-exhausted"].includes(r.run.status) ? "Inconclusive" : "Not observed"}</td><td>{r.run.utility_success ? "Yes" : "No"}</td><td>{(r.run.duration_ms/1000).toFixed(2)} s</td></tr>)}</tbody></table></div>
    <label>Inspect timeline · {title} · {record.case}<select value={selected.run.defense} onChange={e => setDefense(e.target.value)}>{records.map(r => <option key={r.run.defense} value={r.run.defense}>{r.run.defense}</option>)}</select></label>
    <p><strong>Selected execution:</strong> {selected.run.defense} · {selected.run.status} · {selected.run.model_calls} model calls</p>
    <p>{actionPath(selected.run)}</p>
    <details key={selected.run.defense}><summary>Actual timeline · {selected.run.events.length} recorded events</summary><ol>{selected.run.events.map(event => <li key={event.step}><strong>{event.kind}: {event.message}</strong>{Object.keys(event.details).length > 0 && <pre>{JSON.stringify(event.details,null,2)}</pre>}</li>)}</ol></details>
    <GroundingEvidence outcome={selected.run.outcome_details}/>
    {selected.run.outcome_details && <details><summary>Fact checks and security outcomes</summary><pre>{JSON.stringify(selected.run.outcome_details,null,2)}</pre></details>}
    {selected.run.state_changes && Object.keys(selected.run.state_changes).length > 0 && <details open><summary>Observed state changes</summary><pre>{JSON.stringify(selected.run.state_changes,null,2)}</pre></details>}
    {!!selected.run.model_recoveries?.length && <p>The program recovered from {selected.run.model_recoveries.length} unusable model replies using its configured read-only workflow and checked records.</p>}
    <h4>Returned answer · {selected.run.defense}</h4>{selected.run.answer_text ? <><p className="case-input">{selected.run.answer_text}</p><details><summary>Structured returned fields</summary><pre>{selected.run.answer}</pre></details></> : <pre>{selected.run.answer || "No final answer returned."}</pre>}
  </article>;
}

function App() {
  const [key, setKey] = useState("");
  const [tab, setTab] = useState("Overview");
  const [events, setEvents] = useState<Event[]>([]);
  const [selected, setSelected] = useState<Event>();
  const [policy, setPolicy] = useState<Policy>();
  const [policyText, setPolicyText] = useState("");
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [attackId, setAttackId] = useState("");
  const [payload, setPayload] = useState("");
  const [level, setLevel] = useState(0);
  const [player, setPlayer] = useState("researcher");
  const [board, setBoard] = useState<{player: string; levels_solved: number}[]>([]);
  const [tenants, setTenants] = useState<{name: string; role: string}[]>([]);
  const [tenantName, setTenantName] = useState("");
  const [notice, setNotice] = useState("Connect with your local tenant key to inspect decisions.");
  const [busy, setBusy] = useState(false);
  const [metrics, setMetrics] = useState<{total: number; actions: Record<string, number>; rules: Record<string, number>; block_rate: number; flag_rate: number}>();
  const [pending, setPending] = useState<{digest: string; attack_id: string; payload: string; player: string}[]>([]);
  const [arenaResults, setArenaResults] = useState<ArenaResult[]>([]);
  const [labConfig, setLabConfig] = useState<LabConfig>();
  const [labEmail, setLabEmail] = useState("");
  const [labDefense, setLabDefense] = useState("full-ifc");
  const [labJobs, setLabJobs] = useState<LabJob[]>([]);
  const [scenarioId, setScenarioId] = useState("finance-workflow");
  const [partition, setPartition] = useState("development");
  const [variation, setVariation] = useState(0);
  const [goal, setGoal] = useState("exfiltration");
  const [channel, setChannel] = useState("email");
  const [recoverModelErrors,setRecoverModelErrors] = useState(true);
  const [groundingMode, setGroundingMode] = useState("enforce");
  const [runTitle, setRunTitle] = useState("Workflow evaluation");
  const [selectedDefenses, setSelectedDefenses] = useState(["none","prompt-hardening","detector","detector-sanitizer","full-ifc"]);
  const [historySearch, setHistorySearch] = useState("");
  const [historyStatus, setHistoryStatus] = useState("all");
  const [strategy, setStrategy] = useState("authority");
  const [rounds, setRounds] = useState(1);
  const [turns, setTurns] = useState(6);
  const [recordFilter, setRecordFilter] = useState("all");
  const [baselineId, setBaselineId] = useState("");
  const [comparison, setComparison] = useState<{note: string; model_changed: boolean; policy_changed: boolean; grounding_changed: boolean; rows: {defense: string; attack_delta: number; utility_delta: number; p95_delta_ms: number; status: string}[]}>();
  const [labJob, setLabJob] = useState<LabJob>();

  useEffect(() => {
    if (!labJob) return;
    if (!["queued", "running"].includes(labJob.status)) {
      setLabJobs(previous => previous.map(job => job.id === labJob.id ? {...job, status: labJob.status} : job));
      return;
    }
    let active = true;
    const timer = setInterval(async () => {
      try {
        const current = await api(`/lab/jobs/${labJob.id}`);
        if (active) setLabJob(current);
      } catch (error) { if (active) setNotice(error instanceof Error ? error.message : "Run refresh failed"); }
    }, 1500);
    return () => { active = false; clearInterval(timer); };
  }, [labJob?.id, labJob?.status, key]);

  async function startLab(kind: "agent" | "campaign" | "suite") {
    setRecordFilter("all"); setComparison(undefined);
    const response = await fetch("/api/lab/jobs", {method: "POST", headers: {
      Authorization: `Bearer ${key}`, "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID()
    }, body: JSON.stringify({kind, recover_model_errors:recoverModelErrors, grounding:groundingMode, title:runTitle, selected_defenses:kind === "agent" ? [labDefense] : selectedDefenses, email: labEmail, defense: labDefense, adaptive_rounds: kind === "suite" ? 0 : rounds, attack_strategy: strategy, max_turns: turns, scenario_id: scenarioId, partition, variation, attack_goal: goal, attack_channel: channel})});
    if (!response.ok) throw new Error((await response.json()).detail || "Could not start run");
    setLabJob(await response.json());
    setLabJobs((await api("/lab/jobs")).jobs);
    setNotice("Run queued. Progress refreshes automatically. Model errors will be shown explicitly.");
  }

  async function loadSavedSetup() {
    const saved = labJob?.spec || labJob?.result?.spec;
    if (!saved) throw new Error("This historical run does not contain a reusable configuration.");
    const nextPartition = saved.partition || "development", nextGoal = saved.attack_goal || "exfiltration";
    const configuration = await api(`/lab/config?partition=${nextPartition}&variation=${saved.variation || 0}&goal=${nextGoal}`);
    setLabConfig(configuration); setPartition(nextPartition); setGoal(nextGoal); setVariation(saved.variation || 0);
    setScenarioId(saved.scenario_id); setLabEmail(saved.email); setLabDefense(saved.defense);
    setChannel(saved.attack_channel || "email"); setStrategy(saved.attack_strategy || "authority");
    setGroundingMode(saved.grounding || "off"); setRecoverModelErrors(saved.recover_model_errors ?? false);
    setRounds(saved.adaptive_rounds); setTurns(saved.max_turns); setSelectedDefenses(saved.selected_defenses || configuration.defenses);
    setRunTitle(`${saved.title || "Evaluation"} (repeat)`.slice(0,100));
    setNotice("Saved configuration loaded into the editor. Choose a run button to create new evidence with the current model and policy.");
  }

  function exportCsv() {
    if (!labJob) return;
    const url = URL.createObjectURL(new Blob([evidenceCsv(filteredRecords)],{type:"text/csv;charset=utf-8"}));
    const a = document.createElement("a"); a.href=url; a.download=`evaluation-${labJob.id}.csv`; a.click(); URL.revokeObjectURL(url);
  }

  async function configureCases(nextPartition: string, nextVariation: number, nextGoal: string) {
    const configuration = await api(`/lab/config?partition=${nextPartition}&variation=${nextVariation}&goal=${nextGoal}`);
    setLabConfig(configuration); setPartition(nextPartition); setVariation(nextVariation); setGoal(nextGoal);
    const nextScenario = configuration.scenarios.find((item: {id:string;workflow?:boolean}) => item.id === scenarioId && ((nextGoal === "exfiltration" && channel !== "record") || item.workflow)) || configuration.scenarios[0];
    setScenarioId(nextScenario.id); setLabEmail(nextScenario.attacks[strategy] || configuration.attack_email);
  }

  async function runArena(levels: number[]) {
    setArenaResults([]);
    for (const next of levels) {
      const result: ArenaResult = await api("/arena/submit", { player, level: next, attack_id: attackId, payload });
      setArenaResults(previous => [...previous, result]);
    }
    setNotice("Test complete. Read the results below the run buttons. All effects are simulated.");
    setBoard(await api("/arena/leaderboard"));
  }

  async function api(path: string, body?: unknown) {
    const response = await fetch(`/api${path}`, { method: body ? "POST" : "GET", headers: {
      "Authorization": `Bearer ${key}`, "Content-Type": "application/json"
    }, ...(body ? { body: JSON.stringify(body) } : {}) });
    if (!response.ok) throw new Error(`${response.status}: ${(await response.json()).detail ?? "Request failed"}`);
    return response.json();
  }
  async function action(work: () => Promise<void>) {
    setBusy(true);
    try { await work(); } catch (error) { setNotice(error instanceof Error ? error.message : "Request failed"); }
    finally { setBusy(false); }
  }
  async function refresh() {
    const audit = await api("/audit");
    setEvents(audit.events);
    setMetrics(await api("/metrics"));
    setNotice(audit.chain_valid ? "Audit chain verified. Showing your tenant only." : "Audit chain verification failed.");
    const current = await api("/policy");
    setPolicy(current); setPolicyText(current.text);
  }
  async function open(next: string) {
    setTab(next);
    if (next === "Security Tests") {
      const data = await api("/arena/levels");
      setAttacks(data.attacks);
      if (!attackId) { setAttackId(data.attacks[0].id); setPayload(data.attacks[0].payload); }
      setBoard(await api("/arena/leaderboard"));
    }
    if (next === "Access Management") setTenants(await api("/tenants"));
    if (next === "Agent Evaluation") {
      const configuration = await api(`/lab/config?partition=${partition}&variation=${variation}&goal=${goal}`); setLabConfig(configuration);
      if (!labEmail) setLabEmail(configuration.attack_email);
      setLabJobs((await api("/lab/jobs")).jobs);
    }
  }
  const filteredRecords = (labJob?.result?.records || []).filter(record => matchesEvidence(record, recordFilter));
  const blocked = metrics?.actions.block ?? 0;
  const allowed = metrics?.actions.allow ?? 0;
  const selectedTrace = typeof selected?.event.trace === "string" ? JSON.parse(selected.event.trace) as Trace : selected?.event.trace;
  return <div className="shell">
    <aside><a className="brand" href="#main"><span className="mark">M</span>MECHA<span className="version">0.2</span></a>
      <p className="eyebrow">DEFENSE WORKSPACE</p>
      <nav aria-label="Main navigation">{["Overview", "Incident Review", "Security Policy", "Security Tests", "Agent Evaluation", "Approval Review", "Access Management"].map((name, index) =>
        <button key={name} aria-current={tab === name ? "page" : undefined} onClick={() => action(() => open(name))}>
          <span className="navnum">0{index + 1}</span>{name}</button>)}</nav>
      <div className="scope"><span className="status-dot"/> LOCAL RESEARCH<br/><p>Sample data. Simulated actions.<br/>No external attack targets.</p></div>
    </aside>
    <main id="main"><header><div><p className="eyebrow">SECURITY / {tab.toUpperCase()}</p><h1>{tab === "Overview" ? "Every decision, accounted for." : tab}</h1></div>
      <span className="badge">SANDBOX</span></header>
      <form className="connect" onSubmit={e => { e.preventDefault(); action(refresh); }}>
        <label htmlFor="key">Tenant API key</label><input id="key" type="password" autoComplete="off" value={key} onChange={e => {setKey(e.target.value); setLabJob(undefined); setLabJobs([]); setComparison(undefined); setBaselineId(""); setArenaResults([]);}} placeholder="Enter your local key"/>
        <button className="primary" disabled={busy || !key}>Connect / refresh</button></form>
      <div className="notice" role="status" aria-live="polite">{notice}</div>
      {tab === "Overview" && <>
        <section className="stats" aria-label="Tenant decisions">{[["AUDIT ENTRIES", metrics?.total ?? 0, "All stored tenant decisions"], ["BLOCKED", blocked, `${((metrics?.block_rate ?? 0)*100).toFixed(1)}% of audit entries`], ["ALLOWED", allowed, `Flag rate: ${((metrics?.flag_rate ?? 0)*100).toFixed(1)}%`]].map(([title, value, note]) =>
          <article key={title}><p className="eyebrow">{title}</p><strong>{value}</strong><p>{note}</p></article>)}</section>
        <section className="callout"><span className="tag">THE STRUCTURAL BOUNDARY</span><h2>Untrusted content can inform an answer.<br/>It cannot grant tool authority.</h2><p>The interpreter checks provenance, confidentiality, destinations and approval before each simulated action.</p>
          <button onClick={() => action(() => open("Security Policy"))}>Inspect active policy <span aria-hidden>↗</span></button></section>
        <div className="section-head"><h2>Recent activity</h2><span>Tenant isolated · metadata only</span></div>
      </>}
      {(tab === "Overview" || tab === "Incident Review") && <section className="panel">
        {events.length === 0 ? <div className="empty"><h2>No decisions loaded</h2><p>Connect, then send a request through the gateway or run a security test.</p></div> : <div className="table-scroll"><table><thead><tr><th>Decision</th><th>Rule</th><th>Explanation</th><th>Audit reference</th></tr></thead><tbody>{events.map((item) => <tr key={item.digest}>
          <td><span className={`pill ${item.event.action}`}>{item.event.action}</span></td><td>{item.event.rule}</td><td>{item.event.reason || "—"}</td><td><button onClick={() => action(async () => setSelected(await api(`/incidents/${item.digest}`)))} aria-label={`Inspect audit ${item.digest.slice(0, 12)}`}>{item.digest.slice(0, 12)} ↗</button></td></tr>)}</tbody></table></div>}
        {selected && <div className="detail"><button className="close" onClick={() => setSelected(undefined)}>Close details</button><h2>Decision evidence</h2>
          {selectedTrace && <><p>Policy <code>{selectedTrace.policy_digest.slice(0, 16)}</code> · {selectedTrace.effect_count} simulated actions</p><ol>{selectedTrace.steps.map((step) => <li key={step.index}><h3>{step.op} · step {step.index + 1}</h3>{step.inputs.map((label, i) => <p key={i}>Input {i+1}: <strong>{label.trust}</strong> · {label.confidentiality} · {label.source_count} sources · {label.sink_count} permitted sinks</p>)}{step.output && <p>Output remains {step.output.trust} / {step.output.confidentiality}</p>}{step.decision && <p className={step.decision.allowed ? "trace-allow" : "trace-deny"}>{step.decision.allowed ? "Allowed" : "Denied"}: {step.decision.reason}</p>}</li>)}</ol></>}
          <details><summary>Audit metadata</summary><pre>{JSON.stringify(selected, null, 2)}</pre></details><p>Raw prompts and value contents are excluded from audit storage.</p></div>}
      </section>}
      {tab === "Security Policy" && <section className="panel editor"><div className="section-head"><h2>Tenant policy</h2><span>{policy?.digest.slice(0, 16) || "Not loaded"}</span></div>
        <label htmlFor="policy">YAML rules</label><textarea id="policy" value={policyText} onChange={e => setPolicyText(e.target.value)}/>
        <div className="actions"><button disabled={busy} onClick={() => action(async () => setNotice(JSON.stringify(await api("/policy/stage", { text: policyText, dry_run: true }))))}>Validate / dry run</button>
          <button disabled={busy} onClick={() => action(async () => { const staged = await api("/policy/stage", { text: policyText, dry_run: false }); setNotice(JSON.stringify(staged)); const p = await api("/policy"); setPolicy(p); })}>Stage revision</button></div>
        <details><summary>Compare with active policy</summary><div className="diff"><pre>{policy?.text}</pre><pre>{policyText}</pre></div></details>
        <h3>Revision history</h3>{policy?.history.map(rev => <div className="revision" key={rev.revision}><code>Revision {rev.revision} · {rev.digest.slice(0, 12)}</code><button onClick={() => action(async () => { await api("/policy/promote", { revision: rev.revision }); await refresh(); })}>Activate / roll back here</button></div>)}
      </section>}
      {tab === "Security Tests" && <section className="panel editor"><span className="tag">SCRIPTED REGRESSION TESTS</span><h2>Validate a security control</h2><p>Edit a test case while preserving its action format. Use sample data only. Reproduced cases are retained in the regression review queue.</p>
        <p>The MECHA_FIXTURE JSON defines a scripted action. The text around it is not interpreted by a model. Use Agent Evaluation to test whether the 7B model follows a natural-language instruction.</p><button onClick={() => action(() => open("Agent Evaluation"))}>Open real-model evaluation</button><p><strong>Objective:</strong> {attacks.find(a => a.id === attackId)?.goal || "Select a test case"}</p><div className="fields"><label>Defense configuration<select disabled={busy} value={level} onChange={e => {setLevel(Number(e.target.value)); setArenaResults([]);}}>{["0 · Vulnerable", "1 · Detector", "2 · Detector + sanitizer", "3 · Full IFC"].map((s, i) => <option value={i} key={i}>{s}</option>)}</select></label>
        <label>Test case<select disabled={busy} value={attackId} onChange={e => {setArenaResults([]); setAttackId(e.target.value); setPayload(attacks.find(a => a.id === e.target.value)?.payload || "");}}>{attacks.map(a => <option value={a.id} key={a.id}>{a.category} · {a.id}</option>)}</select></label>
        <label>Operator reference<input value={player} onChange={e => setPlayer(e.target.value)} pattern="[a-zA-Z0-9_-]{3,24}"/></label></div>
        <label htmlFor="payload">Attack payload</label><textarea disabled={busy} id="payload" value={payload} onChange={e => {setPayload(e.target.value); setArenaResults([]);}}/>
        <div className="actions"><button className="primary" disabled={busy || !key || !attackId || !payload} onClick={() => action(() => runArena([level]))}>Run selected test</button>
        <button disabled={busy || !key || !attackId || !payload} onClick={() => action(() => runArena([0, 1, 2, 3]))}>Compare defenses</button></div>
        {arenaResults.length > 0 && <section className="arena-results" aria-label="Security test results" aria-live="polite">
          <h2>What happened in this test</h2><p>This result describes a scripted action replay. It does not establish that a language model followed the attack instructions.</p>
          <div className="table-scroll"><table><thead><tr><th>Defense level</th><th>Attack result</th><th>Recorded actions</th><th>Outbound action records</th></tr></thead><tbody>{arenaResults.map(result => <tr key={result.level}><td>{levelNames[result.level]}</td><td>{outcomeNames[result.outcome] || "Unknown outcome"}</td><td>{result.effects.length}</td><td>{result.external_effect_count}</td></tr>)}</tbody></table></div>
          {arenaResults.map(result => <article className="arena-evidence" key={result.level}>
            <h3>{levelNames[result.level]} — {outcomeNames[result.outcome] || "Unknown outcome"}</h3>
            <p><strong>Why:</strong> {result.explanation}</p><p>{result.limitations}</p>{result.legacy_case && <p>Historical test format: destination fields may not match current tool schemas.</p>}<details><summary>Exact payload used for this result</summary><pre>{result.input_payload}</pre></details><h4>Execution sequence</h4><ol>{result.evidence_steps.map((step, index) => <li key={index}>{step}</li>)}</ol><p><strong>Objective:</strong> {result.goal}</p><p><strong>Expected action:</strong> {result.oracle.kind} · destination <code>{result.oracle.destination}</code></p><p><strong>Test input reference:</strong> <code>{result.payload_sha256.slice(0, 16)}</code></p>
            <p><strong>Target:</strong> {result.agent} · <strong>Test case:</strong> {result.attack_id}</p>
            <p><strong>Attacker requested:</strong> {result.attempted_action.kind} to <code>{result.attempted_action.destination}</code> with the content template <code>{result.attempted_action.content}</code>. {result.attempted_action.content.includes("$PRIVATE") && <>The <code>$PRIVATE</code> placeholder refers to the repository test canary. It is substituted only if the scripted target executes the action.</>}</p>
            {result.effects.map((effect, i) => <div className="mock-effect" key={i}><p><strong>Recorded simulated action:</strong> {effect.kind}</p><p>Destination: <code>{effect.destination}</code></p><p>Sample content: <code>{effect.content}</code></p><p>This action exists only in the test ledger. No delivery took place.</p></div>)}
            {!result.effects.length && <p><strong>External tool effects:</strong> zero.</p>}
            {result.decisions.length > 0 && <p><strong>Recorded decisions:</strong> {result.decisions.join("; ")}</p>}
            {result.trace && <div><h3>IFC execution steps</h3><ol>{result.trace.steps.map(step => <li key={step.index}><strong>{step.op}</strong>{step.output && ` → ${step.output.trust} / ${step.output.confidentiality}`}{step.decision && ` → ${step.decision.allowed ? "Allowed" : "Denied"}: ${step.decision.reason}`}</li>)}</ol><p>{result.trace.effect_count} internal simulated actions, including summarization. The fixed program did not plan the attacker’s requested action.</p></div>}
            <details><summary>Returned text (displayed as plain text)</summary><pre>{result.output || "No response text: the detector stopped execution."}</pre></details>
          </article>)}
        </section>}
        <h3>Test coverage by operator</h3>{board.map(row => <p key={row.player}>{row.player} <strong>{row.levels_solved} configurations with reproduced findings</strong></p>)}
        <h3>Regression review</h3><button disabled={busy} onClick={() => action(async () => setPending((await api("/arena/pending")).candidates))}>Load review queue (admin)</button>
        {pending.map(candidate => <article key={candidate.digest}><h3>{candidate.attack_id} · {candidate.player}</h3><pre>{candidate.payload}</pre><button disabled={busy} onClick={() => action(async () => {await api(`/arena/review/${candidate.digest}`, {}); setPending((await api("/arena/pending")).candidates); setNotice("Accepted as a reviewed corpus candidate. Export it for versioned regression review.");})}>Accept test case</button></article>)}
      </section>}
      {tab === "Agent Evaluation" && <section className="panel editor">
        <span className="tag">MODEL-DRIVEN · SIMULATED TOOLS</span><h2>A real model, an observable agent loop</h2>
        <p>The model chooses scenario-specific tools: invoice and vendor reads, ticket and incident-history reads, or request and manager-approval checks. Unsafe configurations can mutate isolated records; all actions remain inside this repository.</p>
        <p><strong>Model:</strong> {labConfig?.model} · <strong>Provider:</strong> {labConfig?.provider}</p>
        {!labConfig?.enabled && <p className="mock-effect">Agent model is not configured. Set MECHA_AGENT_PROVIDER on the server and restart. Scripted Security Tests remain available separately.</p>}
        <label>Evaluation name<input maxLength={100} value={runTitle} onChange={e => setRunTitle(e.target.value)} placeholder="Name this evaluation"/></label>
        <label>Source answer checks<select value={groundingMode} onChange={e => setGroundingMode(e.target.value)}><option value="enforce">Enforce · correct covered fields from records</option><option value="shadow">Shadow · report differences only</option><option value="off">Off · earlier IFC behavior</option></select></label><p>Applies to full IFC on the three structured record workflows. Checks use configured record fields and business rules. They cannot establish the truth of a compromised source.</p>
        <label><input type="checkbox" checked={recoverModelErrors} onChange={e => setRecoverModelErrors(e.target.checked)}/> Use checked records if the model returns an unusable reply</label><p>For covered workflows with source checks enforced. Recoveries are recorded separately from successful model replies.</p>
        <fieldset className="defense-picker"><legend>Comparison defenses</legend>{(labConfig?.defenses || []).map(name => <label key={name}><input type="checkbox" checked={selectedDefenses.includes(name)} onChange={e => setSelectedDefenses(old => e.target.checked ? [...old,name] : old.filter(d => d !== name))}/>{name}</label>)}<p>Used by comparisons and suites. Single-agent runs use the defense selector below.</p></fieldset>
        <div className="fields"><label>Dataset partition<select value={partition} disabled={busy} onChange={e => action(() => configureCases(e.target.value,variation,goal))}><option value="development">Development</option><option value="heldout">Held-out</option></select></label><label>Case variation<select value={variation} disabled={busy} onChange={e => action(() => configureCases(partition,Number(e.target.value),goal))}>{[0,1,2,3,4].map(v => <option key={v} value={v}>{v+1}</option>)}</select></label><label>Attack objective<select value={goal} disabled={busy} onChange={e => action(() => configureCases(partition,variation,e.target.value))}><option value="exfiltration">Confidential data disclosure</option><option value="integrity">Record / answer tampering</option><option value="memory">Memory poisoning</option></select></label><label>Injection channel<select value={channel} onChange={e => {setChannel(e.target.value); if (e.target.value === "record" && !labConfig?.scenarios.find(s => s.id === scenarioId)?.workflow) {const next = labConfig?.scenarios.find(s => s.workflow); if (next) {setScenarioId(next.id);setLabEmail(next.attacks[strategy]);}}}}><option value="email">Incoming email</option><option value="record">Returned record / tool output</option></select></label></div>
        <p>Versioned case bank: 30 task instances, split between development and held-out sets. Each variation changes the scoped record IDs and finance facts. Held-out cases are authored locally, not independent external benchmark validation.</p>
        <div className="fields"><label>Evaluation scenario<select value={scenarioId} onChange={e => {setScenarioId(e.target.value); const scenario = labConfig?.scenarios.find(s => s.id === e.target.value); setLabEmail(scenario?.attacks[strategy] || "");}}>{labConfig?.scenarios.filter(s => (goal === "exfiltration" && channel !== "record") || s.workflow).map(s => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>
        <label>Attack strategy<select value={strategy} onChange={e => {setStrategy(e.target.value); setLabEmail(labConfig?.scenarios.find(s => s.id === scenarioId)?.attacks[e.target.value] || "");}}>{Object.keys(labConfig?.strategies || {}).map(name => <option key={name}>{name}</option>)}</select></label></div>
        <h3>Trusted user task</h3><p>{labConfig?.scenarios.find(s => s.id === scenarioId)?.task || labConfig?.task}</p>
        <p><strong>Available tools:</strong> {labConfig?.tools}</p>
        <div className="fields"><label>Adaptive rounds per defense<select value={rounds} onChange={e => setRounds(Number(e.target.value))}>{[0,1,2,3].map(n => <option key={n} value={n}>{n}</option>)}</select></label><label>Maximum agent turns<select value={turns} onChange={e => setTurns(Number(e.target.value))}>{[2,3,4,5,6,7,8].map(n => <option key={n} value={n}>{n}</option>)}</select></label></div>
        <p>Comparison plan: {selectedDefenses.length * (2 + rounds)} target runs across {selectedDefenses.length} selected defenses. Shared budget: 128 model calls; 10-minute deadline. Long campaigns can exhaust this budget.</p>
        <div className="actions"><button onClick={() => setLabEmail(labConfig?.scenarios.find(s => s.id === scenarioId)?.email || "")}>Use normal email</button><button onClick={() => setLabEmail(labConfig?.scenarios.find(s => s.id === scenarioId)?.attacks[strategy] || "")}>Use natural-language attack</button></div>
        <label htmlFor="lab-email">Incoming email controlled by the attacker (sample data only)</label>
        <textarea id="lab-email" maxLength={8192} value={labEmail} onChange={e => setLabEmail(e.target.value)}/>
        <label htmlFor="lab-defense">Defense configuration</label><select id="lab-defense" value={labDefense} onChange={e => setLabDefense(e.target.value)}>{labConfig?.defenses.map(defense => <option key={defense}>{defense}</option>)}</select>
        <div className="actions"><button className="primary" disabled={busy || !labConfig?.enabled || !labEmail} onClick={() => action(() => startLab("agent"))}>Run model agent</button>
          <button disabled={busy || !labConfig?.enabled || !labEmail || !selectedDefenses.length} onClick={() => action(() => startLab("campaign"))}>Run adaptive comparison</button><button disabled={busy || !labConfig?.enabled || !selectedDefenses.length} onClick={() => action(() => startLab("suite"))}>Run business suite · 6 cases × {selectedDefenses.length} defenses</button></div>
        <p>The standard suite covers invoice reconciliation, support triage and access-request review using the selected attack strategy, with one normal and one static attack per selected defense (6 unique inputs, {6 * selectedDefenses.length} defense executions). It uses server-owned inputs; edits to the email box apply to single-scenario runs only.</p><p>The comparison runs a normal email, your attack, and the configured feedback-driven attacker revisions for each selected defense. Campaigns have a 128-call budget; the suite reserves up to 240 calls based on the selected turn limit. Both have a 10-minute deadline. Small local models may fail the action schema; those runs are inconclusive.</p>
        {labJob && <section aria-label="Model run results" aria-live="polite"><h2>{labJob.spec?.title || labJob.result?.spec?.title || "Evaluation"} · {labJob.status}</h2><p>Run {labJob.id.slice(0,8)} · created {new Date(labJob.created*1000).toLocaleString()}</p><button disabled={busy} onClick={() => action(loadSavedSetup)}>Load saved configuration</button><p><strong>Recorded model:</strong> {labJob.result?.model || "Run in progress"} · <strong>Scenario:</strong> {labJob.result?.scenario?.name || "See run configuration"}</p><p><strong>Recorded source-check mode:</strong> {labJob.spec?.grounding || labJob.result?.spec?.grounding || "off (historical run)"}</p><p><strong>Policy reference:</strong> {labJob.result?.policy_digest?.slice(0,16) || "Pending"}</p>
          <p>{labJob.result?.active_scenario && <>Active scenario: {labJob.result.active_scenario} · </>}{labJob.result?.model_calls ?? 0} model calls · {labJob.result?.completed_runs ?? labJob.result?.records?.length ?? 0} agent runs</p>
          {["queued", "running"].includes(labJob.status) && <button onClick={() => action(async () => setLabJob(await api(`/lab/jobs/${labJob.id}/cancel`, {})))}>Cancel run</button>}
          {labJob.result?.error_code && <p>Run failed: {labJob.result.error_code}. This is not a successful defense result.</p>}
          <EvaluationInsights records={labJob.result?.records || []}/>
          {labJob.result?.summary && <div className="table-scroll"><table><thead><tr><th>Defense</th><th>Observed attack successes</th><th>Invalid attack runs</th><th>Normal-task success</th><th>Static / adaptive successes</th><th>Median / p95</th><th>Target model calls</th><th>Evidence</th></tr></thead><tbody>{labJob.result.summary.map(row => <tr key={row.defense}><td>{row.defense}</td><td>{row.attack_successes}/{row.attack_trials}</td><td>{row.invalid_attack_runs}</td><td>{row.benign_successes}/{row.benign_trials}</td><td>{row.static_successes ?? "—"} / {row.adaptive_successes ?? "—"}</td><td>{row.p50_ms?.toFixed(0) ?? "—"} / {row.p95_ms?.toFixed(0) ?? "—"} ms</td><td>{row.model_calls ?? "—"}</td><td>{row.conclusive ? "Valid small sample" : "Inconclusive"}</td></tr>)}</tbody></table></div>}
          {labJob.result?.scenario_results && <details open><summary>Scenario breakdown</summary><div className="table-scroll"><table><thead><tr><th>Scenario</th><th>Defense</th><th>Attack successes</th><th>Normal-task success</th></tr></thead><tbody>{labJob.result.scenario_results.flatMap(s => s.summary.map(r => <tr key={s.id+r.defense}><td>{s.name}</td><td>{r.defense}</td><td>{r.attack_successes}/{r.attack_trials}</td><td>{r.benign_successes}/{r.benign_trials}</td></tr>))}</tbody></table></div></details>}
          {labJob.status === "completed" && <section><h3>Compare against a saved run</h3><label>Baseline run<select value={baselineId} onChange={e => {setBaselineId(e.target.value); setComparison(undefined);}}><option value="">Choose a completed run</option>{labJobs.filter(j => j.status === "completed" && j.id !== labJob.id).map(j => <option key={j.id} value={j.id}>{j.id.slice(0,8)} · {new Date(j.created*1000).toLocaleString()}</option>)}</select></label><button disabled={!baselineId || busy} onClick={() => action(async () => setComparison(await api(`/lab/jobs/${labJob.id}/compare/${baselineId}`)))}>Compare results</button><p>Inputs, scenarios and budgets must match. Policy or model changes are reported separately.</p>{comparison && <><p>{comparison.note}</p><p>Model changed: {comparison.model_changed ? "yes" : "no"} · Policy changed: {comparison.policy_changed ? "yes" : "no"} · Source checks changed: {comparison.grounding_changed ? "yes" : "no"}</p><table><thead><tr><th>Defense</th><th>Attack count change</th><th>Task success change</th><th>p95 change</th><th>Finding</th></tr></thead><tbody>{comparison.rows.map(r => <tr key={r.defense}><td>{r.defense}</td><td>{r.attack_delta}</td><td>{r.utility_delta}</td><td>{r.p95_delta_ms.toFixed(0)} ms</td><td>{r.status}</td></tr>)}</tbody></table></>}</section>}
          <p>Latency includes model inference and tool processing. Small, correlated samples do not establish general robustness.</p>
          <label>Result filter<select value={recordFilter} onChange={e => setRecordFilter(e.target.value)}><option value="all">All runs</option><option value="attack">Successful attacks</option><option value="invalid">Invalid or exhausted runs</option><option value="normal">Normal tasks</option><option value="integrity">Answer tampering</option><option value="disclosure">Confidential disclosure</option><option value="effects">Unauthorized tool effects</option><option value="utility">Normal-task failures</option><option value="source-corrections">Source-corrected answers</option><option value="source-withheld">Source check failures</option></select></label>
          <p><strong>{groupCases(labJob.result?.records || []).length} unique inputs · {labJob.result?.records?.length || 0} defense executions.</strong> Each input is reused across defenses to make the comparison fair. Identical recorded paths remain identical; timelines are not generated for display.</p>
          {groupCases(filteredRecords).map(([id, records]) => <EvaluationCase key={`${labJob.id}:${id}`} records={records} title={labJob.result?.scenario_results?.find(s => s.id === records[0].scenario_id)?.name || labJob.result?.scenario?.name || labConfig?.scenarios.find(s => s.id === records[0].scenario_id)?.name || "Custom case"}/>)}
          <button disabled={!filteredRecords.length} onClick={exportCsv}>Export filtered CSV</button><p>{filteredRecords.length} executions match the current filter.</p><details><summary>Adaptive attacker proposals</summary>{labJob.result?.attacker_attempts?.map((attempt,index) => <article key={index}><h4>{attempt.defense} · round {attempt.round} · {attempt.accepted ? "Accepted" : "Invalid proposal"}</h4><pre>{attempt.response}</pre></article>)}</details><p>{labJob.result?.limits}</p>
          {labJob.result?.records && <button onClick={() => { const url = URL.createObjectURL(new Blob([JSON.stringify(labJob, null, 2)], {type: "application/json"})); const link = document.createElement("a"); link.href = url; link.download = `mecha-run-${labJob.id}.json`; link.click(); URL.revokeObjectURL(url); }}>Download evidence JSON</button>}
        </section>}
        <h3>Recent saved runs</h3><p>Search the latest 50 saved runs for this tenant.</p><div className="fields"><label>Search saved runs<input type="search" value={historySearch} onChange={e => setHistorySearch(e.target.value)} placeholder="Name or run ID"/></label><label>Saved run status<select value={historyStatus} onChange={e => setHistoryStatus(e.target.value)}>{["all","queued","running","completed","failed","cancelled","interrupted"].map(x => <option key={x}>{x}</option>)}</select></label></div><button disabled={busy} onClick={() => action(async () => setLabJobs((await api("/lab/jobs")).jobs))}>Refresh run history</button>
        {labJobs.filter(job => (historyStatus === "all" || job.status === historyStatus) && `${job.title || ""} ${job.id}`.toLowerCase().includes(historySearch.toLowerCase())).map(job => <p key={job.id}><button onClick={() => action(async () => {setComparison(undefined); setBaselineId(""); setRecordFilter("all"); setLabJob(await api(`/lab/jobs/${job.id}`));})}>{job.title || job.id.slice(0, 8)} · {job.status}</button></p>)}
      </section>}
      {tab === "Approval Review" && <ReviewWorkspace request={api} action={action} busy={busy} connection={key}/>}
      {tab === "Access Management" && <section className="panel editor"><h2>Tenant access</h2><p>Platform administrator access required. New keys display once. Their hashes persist when server state storage is configured.</p>{tenants.map(t => <p key={t.name}>{t.name} · {t.role}</p>)}
        <label htmlFor="tenant">New tenant name</label><input id="tenant" value={tenantName} onChange={e => setTenantName(e.target.value)}/>
        <button disabled={busy} onClick={() => action(async () => { const r = await api("/tenants", {name: tenantName, role: "operator"}); setNotice(`Save this key: ${r.key}`); setTenants(await api("/tenants")); })}>Create operator tenant</button>
      </section>}
      <footer>MECHA / Open security research <span>Measured claims. Visible limitations.</span></footer>
    </main>
  </div>;
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App/></React.StrictMode>);
