import React, {useEffect, useState} from "react";

type Review = {
  id: string; status: string; created: number; expires: number; policy_digest: string;
  proposal: {title?: string; justification?: string; priority?: string; tool: string;
    arguments: {recipient: string; body: string}; labels: Record<string, unknown>;
    reason: string; origin: string};
  history?: {at: number; kind: string; note: string; actor: string}[];
  result: Record<string, unknown>;
};
type Response = {reviews: Review[]; role: string; policy_digest: string};
type Props = {
  request: (path: string, body?: unknown) => Promise<unknown>;
  action: (work: () => Promise<void>) => Promise<void>;
  busy: boolean; connection: string;
};

function download(review: Review) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(review, null, 2)], {type: "application/json"}));
  const a = document.createElement("a"); a.href = url; a.download = `review-${review.id}.json`; a.click(); URL.revokeObjectURL(url);
}

export default function ReviewWorkspace({request, action, busy, connection}: Props) {
  const [data, setData] = useState<Response>({reviews: [], role: "viewer", policy_digest: ""});
  const [selected, setSelected] = useState("");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [sort, setSort] = useState("newest");
  const [now, setNow] = useState(Date.now() / 1000);
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState("Public summary review");
  const [justification, setJustification] = useState("");
  const [priority, setPriority] = useState("normal");
  const [recipient, setRecipient] = useState("team@example.invalid");
  const [body, setBody] = useState("Public project summary for operator review.");
  const [note, setNote] = useState("");
  async function refresh() { setData(await request("/reviews") as Response); }
  useEffect(() => { if (connection) void action(refresh); }, [connection]);
  useEffect(() => { const t = setInterval(() => setNow(Date.now()/1000), 1000); return () => clearInterval(t); }, []);
  const status = (r: Review) => r.status === "pending" && r.expires <= now ? "expired" : r.status;
  const ranks: Record<string, number> = {urgent: 0, high: 1, normal: 2};
  const visible = data.reviews.filter(r => (filter === "all" || status(r) === filter) &&
    [r.id, r.proposal.title, r.proposal.justification, r.proposal.arguments.recipient].join(" ").toLowerCase().includes(search.toLowerCase()))
    .sort((a,b) => sort === "priority" ? (ranks[a.proposal.priority || "normal"] - ranks[b.proposal.priority || "normal"] || b.created-a.created) : sort === "expiry" ? a.expires-b.expires : b.created-a.created);
  const current = visible.find(r => r.id === selected) || visible[0];
  useEffect(() => setNote(""), [current?.id]);
  const pending = data.reviews.filter(r => status(r) === "pending");
  const canWrite = ["operator", "admin"].includes(data.role);
  const currentPending = current && status(current) === "pending";
  const stale = current && current.policy_digest !== data.policy_digest;
  async function mutate(suffix: string, value: unknown) {
    if (!current) return;
    await request(`/reviews/${current.id}/${suffix}`, value); setNote(""); await refresh();
  }
  return <section className="panel editor review-workspace">
    <span className="tag">HUMAN OVERSIGHT</span><h2>Approval workspace</h2>
    <p>Review public-summary proposals before a single simulated action. Priority describes urgency, never permission. Tenant roles identify the operator or administrator; they do not identify individual people.</p>
    <div className="stats"><article><span>AWAITING DECISION</span><strong>{pending.length}</strong><p>Unexpired requests in loaded history</p></article><article><span>HIGH / URGENT</span><strong>{pending.filter(r => ["high","urgent"].includes(r.proposal.priority || "normal")).length}</strong><p>Priority assigned by the submitter</p></article><article><span>EXECUTED</span><strong>{data.reviews.filter(r => status(r) === "executed").length}</strong><p>Simulated effects, no external delivery</p></article></div>
    {canWrite && <details open={creating} onToggle={e => setCreating(e.currentTarget.open)}><summary>Create a review request</summary>
      <div className="fields"><label>Review title<input maxLength={100} value={title} onChange={e => setTitle(e.target.value)}/></label><label>Review priority<select value={priority} onChange={e => setPriority(e.target.value)}><option>normal</option><option>high</option><option>urgent</option></select></label></div>
      <label>Business justification<textarea className="short-text" maxLength={1000} value={justification} onChange={e => setJustification(e.target.value)} placeholder="Why is this action needed? Use sample information only."/></label>
      <label>Proposed recipient<input value={recipient} maxLength={80} onChange={e => setRecipient(e.target.value)}/></label>
      <label>Public summary to review<textarea maxLength={4096} value={body} onChange={e => setBody(e.target.value)}/></label>
      <p>Only reserved example.invalid recipients. Server-assigned labels and confidentiality checks apply. Requests expire after five minutes.</p>
      <button className="primary" disabled={busy || !title.trim() || !body.trim()} onClick={() => action(async () => {
        const created = await request("/reviews", {tool:"send_email", arguments:{recipient,body}, title, justification, priority}) as Review;
        setSelected(created.id); setFilter("all"); setSearch(""); await refresh();
      })}>Submit for review</button>
    </details>}
    <div className="fields"><label>Search reviews<input type="search" value={search} onChange={e => setSearch(e.target.value)} placeholder="Title, recipient, justification or ID"/></label><label>Review status<select value={filter} onChange={e => setFilter(e.target.value)}>{["all","pending","executed","denied","withdrawn","expired","interrupted","failed"].map(x => <option key={x}>{x}</option>)}</select></label><label>Sort reviews<select value={sort} onChange={e => setSort(e.target.value)}><option value="newest">Newest first</option><option value="priority">Priority</option><option value="expiry">Expiry</option></select></label></div>
    <button disabled={busy} onClick={() => action(refresh)}>Refresh approvals</button><p>{visible.length} matching requests · latest 100 retained requests loaded · role: {data.role}</p>
    <div className="review-grid"><div aria-label="Review queue" className="review-queue">{visible.map(r => <button key={r.id} aria-pressed={current?.id === r.id} onClick={() => setSelected(r.id)}><strong>{r.proposal.title || "Public summary review"}</strong><span>{status(r)} · {r.proposal.priority || "normal"}</span><small>{r.proposal.arguments.recipient} · {r.id.slice(0,8)}</small></button>)}{!visible.length && <p>No requests match these filters.</p>}</div>
    {current && <article className="arena-evidence review-detail"><h3>{current.proposal.title || "Public summary review"}</h3><p><span className="pill">{status(current)}</span> · {current.proposal.priority || "normal"} priority · {current.id.slice(0,8)}</p>
      <p><strong>Recipient:</strong> {current.proposal.arguments.recipient}<br/><strong>Justification:</strong> {current.proposal.justification || "Not supplied"}</p>
      <pre className="case-input">{current.proposal.arguments.body}</pre>
      <p>{current.proposal.reason} · {current.proposal.origin}<br/>Created {new Date(current.created*1000).toLocaleString()} · {currentPending ? `${Math.min(300, Math.max(0, Math.ceil(current.expires-now)))} seconds remaining` : `Expires ${new Date(current.expires*1000).toLocaleString()}`}</p>
      {stale && <p role="status">The active policy changed. Create a fresh request for another approval.</p>}
      <details><summary>Bound policy and labels</summary><p>Policy: {current.policy_digest}</p><pre>{JSON.stringify(current.proposal.labels,null,2)}</pre></details>
      {canWrite && <><label>Decision or comment note<textarea className="short-text" value={note} maxLength={1000} onChange={e => setNote(e.target.value)} placeholder="Explain your decision or add context. Notes are retained."/></label><div className="actions">
        <button disabled={busy || !note.trim()} onClick={() => action(() => mutate("notes",{note}))}>Add comment</button>
        {currentPending && <>
          {data.role === "admin" && <><button className="primary" disabled={busy || !note.trim() || !!stale} onClick={() => action(() => mutate("decision",{approve:true,note}))}>Approve simulated action</button><button disabled={busy || !note.trim() || !!stale} onClick={() => action(() => mutate("decision",{approve:false,note}))}>Deny action</button></>}
          <button disabled={busy || !note.trim()} onClick={() => action(() => mutate("withdraw",{note}))}>Withdraw request</button>
        </>}
      </div></>}
      <div className="actions"><button onClick={() => download({...current,status:status(current)})}>Export review JSON</button>{canWrite && <button onClick={() => {
        setCreating(true); setTitle(`${current.proposal.title || "Public summary"} (revised)`.slice(0,100)); setJustification(current.proposal.justification || ""); setPriority(current.proposal.priority || "normal"); setRecipient(current.proposal.arguments.recipient); setBody(current.proposal.arguments.body);
      }}>Copy into new request</button>}</div>
      <details open><summary>Review history · {current.history?.length || 0} events</summary><ol>{current.history?.map((e,i) => <li key={i}><strong>{e.kind}</strong> · {e.actor} · {new Date(e.at*1000).toLocaleString()}{e.note && <p>{e.note}</p>}</li>)}</ol>{!current.history?.length && <p>This request predates review-history tracking.</p>}</details>
      <details><summary>Execution result</summary><pre>{JSON.stringify(current.result,null,2)}</pre></details>
    </article>}</div>
  </section>;
}
