import React, { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

type Label = { trust: string; confidentiality: string; source_count: number; sink_count: number };
type Trace = { policy_digest: string; effect_count: number; steps: { index: number; op: string; inputs: Label[]; output?: Label; decision?: {allowed: boolean; reason: string; rule: string} }[] };
type Event = { event: { action: string; rule: string; reason?: string; duration_ms?: number; trace?: Trace | string }; digest: string };
type Attack = { id: string; payload: string; category: string };
type Policy = { text: string; digest: string; history: { revision: number; digest: string }[] };
type ArenaResult = {
  level: number; defense: string; agent: string; attack_id: string; success: boolean;
  explanation: string; decisions: string[]; output: string;
  attempted_action: {kind: string; destination: string; content: string};
  effects: {kind: string; destination: string; content: string}[]; trace?: Trace;
};
const levelNames = ["0 · Vulnerable", "1 · Detector", "2 · Detector + sanitizer", "3 · Full IFC"];
type ModelRun = {defense: string; status: string; attack_success: boolean; utility_success: boolean;
  model_calls: number; duration_ms: number; answer: string; error_code?: string;
  events: {step: number; kind: string; message: string; details: Record<string, unknown>}[];
  effects: {tool: string; recipient: string; body: string}[]};
type LabJob = {id: string; status: string; created: number; result?: {model_calls?: number;
  completed_runs?: number; attacker_errors?: number; error_code?: string; limits?: string;
  summary?: {defense: string; attack_trials: number; attack_successes: number;
    invalid_attack_runs: number; benign_trials: number; benign_successes: number; conclusive: boolean}[];
  records?: {case: string; round?: number; run: ModelRun}[]}};
type LabConfig = {enabled: boolean; provider: string; model: string; task: string;
  attack_email: string; benign_email: string; defenses: string[]};

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

  async function startLab(kind: "agent" | "campaign") {
    const response = await fetch("/api/lab/jobs", {method: "POST", headers: {
      Authorization: `Bearer ${key}`, "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID()
    }, body: JSON.stringify({kind, email: labEmail, defense: labDefense, adaptive_rounds: 1})});
    if (!response.ok) throw new Error((await response.json()).detail || "Could not start run");
    setLabJob(await response.json());
    setLabJobs((await api("/lab/jobs")).jobs);
    setNotice("Run queued. Progress refreshes automatically. Model errors will be shown explicitly.");
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
    if (next === "Arena") {
      const data = await api("/arena/levels");
      setAttacks(data.attacks);
      if (!attackId) { setAttackId(data.attacks[0].id); setPayload(data.attacks[0].payload); }
      setBoard(await api("/arena/leaderboard"));
    }
    if (next === "Tenants") setTenants(await api("/tenants"));
    if (next === "Agent Lab") {
      const configuration = await api("/lab/config"); setLabConfig(configuration);
      if (!labEmail) setLabEmail(configuration.attack_email);
      setLabJobs((await api("/lab/jobs")).jobs);
    }
  }
  const blocked = metrics?.actions.block ?? 0;
  const allowed = metrics?.actions.allow ?? 0;
  const selectedTrace = typeof selected?.event.trace === "string" ? JSON.parse(selected.event.trace) as Trace : selected?.event.trace;
  return <div className="shell">
    <aside><a className="brand" href="#main"><span className="mark">M</span>MECHA<span className="version">0.2</span></a>
      <p className="eyebrow">DEFENSE WORKSPACE</p>
      <nav aria-label="Main navigation">{["Overview", "Incidents", "Policy", "Arena", "Agent Lab", "Tenants"].map((name, index) =>
        <button key={name} aria-current={tab === name ? "page" : undefined} onClick={() => action(() => open(name))}>
          <span className="navnum">0{index + 1}</span>{name}</button>)}</nav>
      <div className="scope"><span className="status-dot"/> LOCAL RESEARCH<br/><p>Sample data. Simulated actions.<br/>No external attack targets.</p></div>
    </aside>
    <main id="main"><header><div><p className="eyebrow">SECURITY / {tab.toUpperCase()}</p><h1>{tab === "Overview" ? "Every decision, accounted for." : tab}</h1></div>
      <span className="badge">SANDBOX</span></header>
      <form className="connect" onSubmit={e => { e.preventDefault(); action(refresh); }}>
        <label htmlFor="key">Tenant API key</label><input id="key" type="password" autoComplete="off" value={key} onChange={e => {setKey(e.target.value); setLabJob(undefined); setLabJobs([]); setArenaResults([]);}} placeholder="Enter your local key"/>
        <button className="primary" disabled={busy || !key}>Connect / refresh</button></form>
      <div className="notice" role="status" aria-live="polite">{notice}</div>
      {tab === "Overview" && <>
        <section className="stats" aria-label="Tenant decisions">{[["AUDIT ENTRIES", metrics?.total ?? 0, "All stored tenant decisions"], ["BLOCKED", blocked, `${((metrics?.block_rate ?? 0)*100).toFixed(1)}% of audit entries`], ["ALLOWED", allowed, `Flag rate: ${((metrics?.flag_rate ?? 0)*100).toFixed(1)}%`]].map(([title, value, note]) =>
          <article key={title}><p className="eyebrow">{title}</p><strong>{value}</strong><p>{note}</p></article>)}</section>
        <section className="callout"><span className="tag">THE STRUCTURAL BOUNDARY</span><h2>Untrusted content can inform an answer.<br/>It cannot grant tool authority.</h2><p>The interpreter checks provenance, confidentiality, destinations and approval before each simulated action.</p>
          <button onClick={() => action(() => open("Policy"))}>Inspect active policy <span aria-hidden>↗</span></button></section>
        <div className="section-head"><h2>Recent activity</h2><span>Tenant isolated · metadata only</span></div>
      </>}
      {(tab === "Overview" || tab === "Incidents") && <section className="panel">
        {events.length === 0 ? <div className="empty"><h2>No decisions loaded</h2><p>Connect, then send a request through the gateway or try an arena fixture.</p></div> : <div className="table-scroll"><table><thead><tr><th>Decision</th><th>Rule</th><th>Explanation</th><th>Audit reference</th></tr></thead><tbody>{events.map((item) => <tr key={item.digest}>
          <td><span className={`pill ${item.event.action}`}>{item.event.action}</span></td><td>{item.event.rule}</td><td>{item.event.reason || "—"}</td><td><button onClick={() => action(async () => setSelected(await api(`/incidents/${item.digest}`)))} aria-label={`Inspect audit ${item.digest.slice(0, 12)}`}>{item.digest.slice(0, 12)} ↗</button></td></tr>)}</tbody></table></div>}
        {selected && <div className="detail"><button className="close" onClick={() => setSelected(undefined)}>Close details</button><h2>Decision evidence</h2>
          {selectedTrace && <><p>Policy <code>{selectedTrace.policy_digest.slice(0, 16)}</code> · {selectedTrace.effect_count} simulated actions</p><ol>{selectedTrace.steps.map((step) => <li key={step.index}><h3>{step.op} · step {step.index + 1}</h3>{step.inputs.map((label, i) => <p key={i}>Input {i+1}: <strong>{label.trust}</strong> · {label.confidentiality} · {label.source_count} sources · {label.sink_count} permitted sinks</p>)}{step.output && <p>Output remains {step.output.trust} / {step.output.confidentiality}</p>}{step.decision && <p className={step.decision.allowed ? "trace-allow" : "trace-deny"}>{step.decision.allowed ? "Allowed" : "Denied"}: {step.decision.reason}</p>}</li>)}</ol></>}
          <details><summary>Audit metadata</summary><pre>{JSON.stringify(selected, null, 2)}</pre></details><p>Raw prompts and value contents are excluded from audit storage.</p></div>}
      </section>}
      {tab === "Policy" && <section className="panel editor"><div className="section-head"><h2>Tenant policy</h2><span>{policy?.digest.slice(0, 16) || "Not loaded"}</span></div>
        <label htmlFor="policy">YAML rules</label><textarea id="policy" value={policyText} onChange={e => setPolicyText(e.target.value)}/>
        <div className="actions"><button disabled={busy} onClick={() => action(async () => setNotice(JSON.stringify(await api("/policy/stage", { text: policyText, dry_run: true }))))}>Validate / dry run</button>
          <button disabled={busy} onClick={() => action(async () => { const staged = await api("/policy/stage", { text: policyText, dry_run: false }); setNotice(JSON.stringify(staged)); const p = await api("/policy"); setPolicy(p); })}>Stage revision</button></div>
        <details><summary>Compare with active policy</summary><div className="diff"><pre>{policy?.text}</pre><pre>{policyText}</pre></div></details>
        <h3>Revision history</h3>{policy?.history.map(rev => <div className="revision" key={rev.revision}><code>Revision {rev.revision} · {rev.digest.slice(0, 12)}</code><button onClick={() => action(async () => { await api("/policy/promote", { revision: rev.revision }); await refresh(); })}>Activate / roll back here</button></div>)}
      </section>}
      {tab === "Arena" && <section className="panel editor"><span className="tag">SECURITY CHALLENGES · SIMULATED TOOLS</span><h2>Test a defense boundary</h2><p>Edit a test case while preserving its action format. Use sample data only. Successful payloads are retained in the tenant review queue.</p>
        <div className="fields"><label>Level<select value={level} onChange={e => setLevel(Number(e.target.value))}>{["0 · Vulnerable", "1 · Detector", "2 · Detector + sanitizer", "3 · Full IFC"].map((s, i) => <option value={i} key={i}>{s}</option>)}</select></label>
        <label>Fixture<select value={attackId} onChange={e => {setAttackId(e.target.value); setPayload(attacks.find(a => a.id === e.target.value)?.payload || "");}}>{attacks.map(a => <option value={a.id} key={a.id}>{a.id}</option>)}</select></label>
        <label>Pseudonym<input value={player} onChange={e => setPlayer(e.target.value)} pattern="[a-zA-Z0-9_-]{3,24}"/></label></div>
        <label htmlFor="payload">Attack payload</label><textarea id="payload" value={payload} onChange={e => setPayload(e.target.value)}/>
        <div className="actions"><button className="primary" disabled={busy} onClick={() => action(() => runArena([level]))}>Run sandbox attempt</button>
        <button disabled={busy} onClick={() => action(() => runArena([0, 1, 2, 3]))}>Compare all four levels</button></div>
        {arenaResults.length > 0 && <section className="arena-results" aria-label="Arena test results" aria-live="polite">
          <h2>What happened in this test</h2><p>This is a deterministic fixture demonstration. No real LLM, email service or collector is contacted.</p>
          <div className="table-scroll"><table><thead><tr><th>Defense level</th><th>Attack result</th><th>Simulated external actions</th></tr></thead><tbody>{arenaResults.map(result => <tr key={result.level}><td>{levelNames[result.level]}</td><td>{result.success ? "Sample data disclosed" : "No unauthorized effect"}</td><td>{result.effects.length}</td></tr>)}</tbody></table></div>
          {arenaResults.map(result => <article className="arena-evidence" key={result.level}>
            <h3>{levelNames[result.level]} — {result.success ? "Attack succeeded" : "No unauthorized effect"}</h3>
            <p><strong>Why:</strong> {result.explanation}</p>
            <p><strong>Target:</strong> {result.agent} · <strong>Fixture:</strong> {result.attack_id}</p>
            <p><strong>Attacker requested:</strong> {result.attempted_action.kind} to <code>{result.attempted_action.destination}</code> using <code>{result.attempted_action.content}</code>.</p>
            {result.effects.map((effect, i) => <div className="mock-effect" key={i}><p><strong>Recorded simulated action:</strong> {effect.kind}</p><p>Destination: <code>{effect.destination}</code></p><p>Sample content: <code>{effect.content}</code></p><p>This is an in-memory record, not a delivered message.</p></div>)}
            {!result.effects.length && <p><strong>External tool effects:</strong> zero.</p>}
            {result.decisions.length > 0 && <p><strong>Recorded decisions:</strong> {result.decisions.join("; ")}</p>}
            {result.trace && <div><h3>IFC execution steps</h3><ol>{result.trace.steps.map(step => <li key={step.index}><strong>{step.op}</strong>{step.output && ` → ${step.output.trust} / ${step.output.confidentiality}`}{step.decision && ` → ${step.decision.allowed ? "Allowed" : "Denied"}: ${step.decision.reason}`}</li>)}</ol><p>{result.trace.effect_count} internal simulated actions, including summarization. No email call was planned.</p></div>}
            <details><summary>Returned text (displayed as plain text)</summary><pre>{result.output || "No response text: the detector stopped execution."}</pre></details>
          </article>)}
        </section>}
        <h3>Leaderboard</h3>{board.map(row => <p key={row.player}>{row.player} <strong>{row.levels_solved} levels solved</strong></p>)}
        <h3>Corpus review</h3><button disabled={busy} onClick={() => action(async () => setPending((await api("/arena/pending")).candidates))}>Load review queue (admin)</button>
        {pending.map(candidate => <article key={candidate.digest}><h3>{candidate.attack_id} · {candidate.player}</h3><pre>{candidate.payload}</pre><button disabled={busy} onClick={() => action(async () => {await api(`/arena/review/${candidate.digest}`, {}); setPending((await api("/arena/pending")).candidates); setNotice("Accepted as a reviewed corpus candidate. Export it for versioned regression review.");})}>Accept test case</button></article>)}
      </section>}
      {tab === "Agent Lab" && <section className="panel editor">
        <span className="tag">MODEL-DRIVEN · SIMULATED TOOLS</span><h2>A real model, an observable agent loop</h2>
        <p>The configured model chooses actions over multiple turns. It can read an incoming email, read a sample confidential memo, and propose a simulated email. No real email or external tool is available.</p>
        <p><strong>Model:</strong> {labConfig?.model} · <strong>Provider:</strong> {labConfig?.provider}</p>
        {!labConfig?.enabled && <p className="mock-effect">Agent model is not configured. Set MECHA_AGENT_PROVIDER on the server and restart. Fixture Arena remains available separately.</p>}
        <h3>Trusted user task</h3><p>{labConfig?.task}</p>
        <div className="actions"><button onClick={() => setLabEmail(labConfig?.benign_email || "")}>Use normal email</button><button onClick={() => setLabEmail(labConfig?.attack_email || "")}>Use natural-language attack</button></div>
        <label htmlFor="lab-email">Incoming email controlled by the attacker (sample data only)</label>
        <textarea id="lab-email" maxLength={8192} value={labEmail} onChange={e => setLabEmail(e.target.value)}/>
        <label htmlFor="lab-defense">Defense configuration</label><select id="lab-defense" value={labDefense} onChange={e => setLabDefense(e.target.value)}>{labConfig?.defenses.map(defense => <option key={defense}>{defense}</option>)}</select>
        <div className="actions"><button className="primary" disabled={busy || !labConfig?.enabled || !labEmail} onClick={() => action(() => startLab("agent"))}>Run model agent</button>
          <button disabled={busy || !labConfig?.enabled || !labEmail} onClick={() => action(() => startLab("campaign"))}>Run adaptive comparison</button></div>
        <p>The comparison runs a normal email, your attack, and one feedback-driven attacker revision for each of five defenses. It has a 128-call budget and a 10-minute deadline. Small local models may fail the action schema; those runs are inconclusive.</p>
        {labJob && <section aria-label="Model run results" aria-live="polite"><h2>Run {labJob.id.slice(0, 8)} · {labJob.status}</h2>
          <p>{labJob.result?.model_calls ?? 0} model calls · {labJob.result?.completed_runs ?? labJob.result?.records?.length ?? 0} agent runs</p>
          {["queued", "running"].includes(labJob.status) && <button onClick={() => action(async () => setLabJob(await api(`/lab/jobs/${labJob.id}/cancel`, {})))}>Cancel run</button>}
          {labJob.result?.error_code && <p>Run failed: {labJob.result.error_code}. This is not a successful defense result.</p>}
          {labJob.result?.summary && <div className="table-scroll"><table><thead><tr><th>Defense</th><th>Observed attack successes</th><th>Invalid attack runs</th><th>Normal-task success</th><th>Evidence</th></tr></thead><tbody>{labJob.result.summary.map(row => <tr key={row.defense}><td>{row.defense}</td><td>{row.attack_successes}/{row.attack_trials}</td><td>{row.invalid_attack_runs}</td><td>{row.benign_successes}/{row.benign_trials}</td><td>{row.conclusive ? "Valid small sample" : "Inconclusive"}</td></tr>)}</tbody></table></div>}
          {labJob.result?.records?.map((record, index) => <article className="arena-evidence" key={index}>
            <h3>{record.run.defense} · {record.case === "benign" ? "Normal task" : record.case} {record.round || ""} · {record.run.status}</h3>
            <p>{record.run.attack_success ? "Unauthorized simulated action or canary disclosure observed." : ["error", "budget-exhausted"].includes(record.run.status) ? "Model run failed; no security conclusion." : "No unauthorized effect observed in this run."}</p>
            <p>{record.run.model_calls} model calls · {(record.run.duration_ms / 1000).toFixed(2)} seconds · Requested task completed: {record.run.utility_success ? "yes" : "no"}</p>
            <h3>Agent timeline</h3><ol>{record.run.events.map(event => <li key={event.step}><strong>{event.kind}: {event.message}</strong>{Object.keys(event.details).length > 0 && <pre>{JSON.stringify(event.details, null, 2)}</pre>}</li>)}</ol>
            <h3>Final answer</h3><pre>{record.run.answer || "No final answer returned."}</pre>
          </article>)}
          <p>{labJob.result?.limits}</p>
          {labJob.result?.records && <button onClick={() => { const url = URL.createObjectURL(new Blob([JSON.stringify(labJob, null, 2)], {type: "application/json"})); const link = document.createElement("a"); link.href = url; link.download = `mecha-run-${labJob.id}.json`; link.click(); URL.revokeObjectURL(url); }}>Download evidence JSON</button>}
        </section>}
        <h3>Recent saved runs</h3><button disabled={busy} onClick={() => action(async () => setLabJobs((await api("/lab/jobs")).jobs))}>Refresh run history</button>
        {labJobs.map(job => <p key={job.id}><button onClick={() => action(async () => setLabJob(await api(`/lab/jobs/${job.id}`)))}>{job.id.slice(0, 8)} · {job.status}</button></p>)}
      </section>}
      {tab === "Tenants" && <section className="panel editor"><h2>Tenant access</h2><p>Platform administrator access required. New keys display once. Their hashes persist when server state storage is configured.</p>{tenants.map(t => <p key={t.name}>{t.name} · {t.role}</p>)}
        <label htmlFor="tenant">New tenant name</label><input id="tenant" value={tenantName} onChange={e => setTenantName(e.target.value)}/>
        <button disabled={busy} onClick={() => action(async () => { const r = await api("/tenants", {name: tenantName, role: "operator"}); setNotice(`Save this key: ${r.key}`); setTenants(await api("/tenants")); })}>Create operator tenant</button>
      </section>}
      <footer>MECHA / Open security research <span>Measured claims. Visible limitations.</span></footer>
    </main>
  </div>;
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App/></React.StrictMode>);
