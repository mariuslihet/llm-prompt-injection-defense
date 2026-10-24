import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

type Label = { trust: string; confidentiality: string; source_count: number; sink_count: number };
type Trace = { policy_digest: string; effect_count: number; steps: { index: number; op: string; inputs: Label[]; output?: Label; decision?: {allowed: boolean; reason: string; rule: string} }[] };
type Event = { event: { action: string; rule: string; reason?: string; duration_ms?: number; trace?: Trace | string }; digest: string };
type Attack = { id: string; payload: string; category: string };
type Policy = { text: string; digest: string; history: { revision: number; digest: string }[] };

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
  const [player, setPlayer] = useState("fake_researcher");
  const [board, setBoard] = useState<{player: string; levels_solved: number}[]>([]);
  const [tenants, setTenants] = useState<{name: string; role: string}[]>([]);
  const [tenantName, setTenantName] = useState("");
  const [notice, setNotice] = useState("Connect with your local tenant key to inspect decisions.");
  const [busy, setBusy] = useState(false);
  const [metrics, setMetrics] = useState<{total: number; actions: Record<string, number>; rules: Record<string, number>; block_rate: number; flag_rate: number}>();
  const [pending, setPending] = useState<{digest: string; attack_id: string; payload: string; player: string}[]>([]);

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
  }
  const blocked = metrics?.actions.block ?? 0;
  const allowed = metrics?.actions.allow ?? 0;
  const selectedTrace = typeof selected?.event.trace === "string" ? JSON.parse(selected.event.trace) as Trace : selected?.event.trace;
  return <div className="shell">
    <aside><a className="brand" href="#main"><span className="mark">M</span>MECHA<span className="version">0.1</span></a>
      <p className="eyebrow">DEFENSE WORKSPACE</p>
      <nav aria-label="Main navigation">{["Overview", "Incidents", "Policy", "Arena", "Tenants"].map((name, index) =>
        <button key={name} aria-current={tab === name ? "page" : undefined} onClick={() => action(() => open(name))}>
          <span className="navnum">0{index + 1}</span>{name}</button>)}</nav>
      <div className="scope"><span className="status-dot"/> LOCAL RESEARCH<br/><p>Fake data. Mock effects.<br/>No external attack targets.</p></div>
    </aside>
    <main id="main"><header><div><p className="eyebrow">SECURITY / {tab.toUpperCase()}</p><h1>{tab === "Overview" ? "Every decision, accounted for." : tab}</h1></div>
      <span className="badge">SANDBOX</span></header>
      <form className="connect" onSubmit={e => { e.preventDefault(); action(refresh); }}>
        <label htmlFor="key">Tenant API key</label><input id="key" type="password" autoComplete="off" value={key} onChange={e => setKey(e.target.value)} placeholder="Enter your local key"/>
        <button className="primary" disabled={busy || !key}>Connect / refresh</button></form>
      <div className="notice" role="status" aria-live="polite">{notice}</div>
      {tab === "Overview" && <>
        <section className="stats" aria-label="Tenant decisions">{[["AUDIT ENTRIES", metrics?.total ?? 0, "All stored tenant decisions"], ["BLOCKED", blocked, `${((metrics?.block_rate ?? 0)*100).toFixed(1)}% of audit entries`], ["ALLOWED", allowed, `Flag rate: ${((metrics?.flag_rate ?? 0)*100).toFixed(1)}%`]].map(([title, value, note]) =>
          <article key={title}><p className="eyebrow">{title}</p><strong>{value}</strong><p>{note}</p></article>)}</section>
        <section className="callout"><span className="tag">THE STRUCTURAL BOUNDARY</span><h2>Untrusted content can inform an answer.<br/>It cannot grant tool authority.</h2><p>The interpreter checks provenance, confidentiality, destinations and approval before each mock effect.</p>
          <button onClick={() => action(() => open("Policy"))}>Inspect active policy <span aria-hidden>↗</span></button></section>
        <div className="section-head"><h2>Recent activity</h2><span>Tenant isolated · metadata only</span></div>
      </>}
      {(tab === "Overview" || tab === "Incidents") && <section className="panel">
        {events.length === 0 ? <div className="empty"><h2>No decisions loaded</h2><p>Connect, then send a request through the gateway or try an arena fixture.</p></div> : <div className="table-scroll"><table><thead><tr><th>Decision</th><th>Rule</th><th>Explanation</th><th>Audit reference</th></tr></thead><tbody>{events.map((item) => <tr key={item.digest}>
          <td><span className={`pill ${item.event.action}`}>{item.event.action}</span></td><td>{item.event.rule}</td><td>{item.event.reason || "—"}</td><td><button onClick={() => action(async () => setSelected(await api(`/incidents/${item.digest}`)))} aria-label={`Inspect audit ${item.digest.slice(0, 12)}`}>{item.digest.slice(0, 12)} ↗</button></td></tr>)}</tbody></table></div>}
        {selected && <div className="detail"><button className="close" onClick={() => setSelected(undefined)}>Close details</button><h2>Decision evidence</h2>
          {selectedTrace && <><p>Policy <code>{selectedTrace.policy_digest.slice(0, 16)}</code> · {selectedTrace.effect_count} mock effects</p><ol>{selectedTrace.steps.map((step) => <li key={step.index}><h3>{step.op} · step {step.index + 1}</h3>{step.inputs.map((label, i) => <p key={i}>Input {i+1}: <strong>{label.trust}</strong> · {label.confidentiality} · {label.source_count} sources · {label.sink_count} permitted sinks</p>)}{step.output && <p>Output remains {step.output.trust} / {step.output.confidentiality}</p>}{step.decision && <p className={step.decision.allowed ? "trace-allow" : "trace-deny"}>{step.decision.allowed ? "Allowed" : "Denied"}: {step.decision.reason}</p>}</li>)}</ol></>}
          <details><summary>Audit metadata</summary><pre>{JSON.stringify(selected, null, 2)}</pre></details><p>Raw prompts and value contents are excluded from audit storage.</p></div>}
      </section>}
      {tab === "Policy" && <section className="panel editor"><div className="section-head"><h2>Tenant policy</h2><span>{policy?.digest.slice(0, 16) || "Not loaded"}</span></div>
        <label htmlFor="policy">YAML rules</label><textarea id="policy" value={policyText} onChange={e => setPolicyText(e.target.value)}/>
        <div className="actions"><button disabled={busy} onClick={() => action(async () => setNotice(JSON.stringify(await api("/policy/stage", { text: policyText, dry_run: true }))))}>Validate / dry run</button>
          <button disabled={busy} onClick={() => action(async () => { const staged = await api("/policy/stage", { text: policyText, dry_run: false }); setNotice(JSON.stringify(staged)); const p = await api("/policy"); setPolicy(p); })}>Stage revision</button></div>
        <details><summary>Compare with active policy</summary><div className="diff"><pre>{policy?.text}</pre><pre>{policyText}</pre></div></details>
        <h3>Revision history</h3>{policy?.history.map(rev => <div className="revision" key={rev.revision}><code>Revision {rev.revision} · {rev.digest.slice(0, 12)}</code><button onClick={() => action(async () => { await api("/policy/promote", { revision: rev.revision }); await refresh(); })}>Activate / roll back here</button></div>)}
      </section>}
      {tab === "Arena" && <section className="panel editor"><span className="tag">LOCAL CTF · MOCK TOOLS ONLY</span><h2>Test a defense boundary</h2><p>Mutate a selected fixture while preserving its fake command. Use fake data only. Successful payloads are retained in the tenant review queue.</p>
        <div className="fields"><label>Level<select value={level} onChange={e => setLevel(Number(e.target.value))}>{["0 · Vulnerable", "1 · Detector", "2 · Detector + sanitizer", "3 · Full IFC"].map((s, i) => <option value={i} key={i}>{s}</option>)}</select></label>
        <label>Fixture<select value={attackId} onChange={e => {setAttackId(e.target.value); setPayload(attacks.find(a => a.id === e.target.value)?.payload || "");}}>{attacks.map(a => <option value={a.id} key={a.id}>{a.id}</option>)}</select></label>
        <label>Pseudonym<input value={player} onChange={e => setPlayer(e.target.value)} pattern="[a-zA-Z0-9_-]{3,24}"/></label></div>
        <label htmlFor="payload">Fake-data payload</label><textarea id="payload" value={payload} onChange={e => setPayload(e.target.value)}/>
        <button className="primary" disabled={busy} onClick={() => action(async () => { const r = await api("/arena/submit", { player, level, attack_id: attackId, payload }); setNotice(r.success ? "Attack succeeded against this mock level. Saved for human review." : "No unauthorized mock effect observed at this level."); setBoard(await api("/arena/leaderboard")); })}>Run sandbox attempt</button>
        <h3>Leaderboard</h3>{board.map(row => <p key={row.player}>{row.player} <strong>{row.levels_solved} levels solved</strong></p>)}
        <h3>Corpus review</h3><button disabled={busy} onClick={() => action(async () => setPending((await api("/arena/pending")).candidates))}>Load review queue (admin)</button>
        {pending.map(candidate => <article key={candidate.digest}><h3>{candidate.attack_id} · {candidate.player}</h3><pre>{candidate.payload}</pre><button disabled={busy} onClick={() => action(async () => {await api(`/arena/review/${candidate.digest}`, {}); setPending((await api("/arena/pending")).candidates); setNotice("Accepted as a reviewed corpus candidate. Export it for versioned regression review.");})}>Accept fake-data candidate</button></article>)}
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
