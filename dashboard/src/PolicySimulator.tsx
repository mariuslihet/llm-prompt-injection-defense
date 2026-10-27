import React, {useEffect, useRef, useState} from "react";

type Item = {value:string; origin:string; private:boolean; sink_allowed:boolean};
type Decision = {allowed:boolean; rule:string; reason:string; needs_approval:boolean};
type Simulation = {policy_digest:string; policy_mode:string; tool:string; read_untrusted:boolean; without_approval:Decision; with_approval:Decision; simulated:boolean; scope:string};
type Props = {request:(path:string, body?:unknown)=>Promise<Simulation>; action:(work:()=>Promise<void>)=>Promise<void>; busy:boolean; connection:string};
const labels:Record<string,string> = {recipient:"Recipient",body:"Message",url:"URL"};

function explain(decision:Decision):string {
  if (decision.needs_approval) return "Human approval is required after untrusted content was read.";
  if (decision.reason.startsWith("untrusted destination")) return "The destination comes from untrusted content. Approval cannot change that.";
  if (decision.reason.startsWith("private egress")) return "Private data cannot be sent to this external tool, even with approval.";
  if (decision.reason.startsWith("sink capability missing")) return "The value has no capability for this tool. Approval cannot add it.";
  if (decision.reason.startsWith("URL denied")) return "The URL is outside the policy allowlist or is invalid.";
  if (decision.allowed) return "The policy constraints for this example are satisfied.";
  return decision.reason;
}

export default function PolicySimulator({request,action,busy,connection}:Props) {
  const [tool,setTool] = useState("send_email");
  const [context,setContext] = useState(true);
  const [items,setItems] = useState<Record<string,Item>>({
    recipient:{value:"team@example.invalid",origin:"trusted",private:false,sink_allowed:true},
    body:{value:"Sample public summary",origin:"untrusted",private:false,sink_allowed:true},
    url:{value:"https://docs.example.invalid/report",origin:"trusted",private:false,sink_allowed:true},
  });
  const [result,setResult] = useState<Simulation>();
  const revision=useRef(0);
  useEffect(()=>{revision.current++;setResult(undefined);},[connection]);
  const names=tool === "send_email" ? ["recipient","body"] : ["url"];
  function update(name:string,patch:Partial<Item>) {revision.current++;setResult(undefined);setItems(old=>({...old,[name]:{...old[name],...patch}}));}
  async function run() {
    const current=++revision.current; setResult(undefined);
    const response=await request("/policy/simulate",{tool,untrusted_context:context,arguments:Object.fromEntries(names.map(name=>[name,items[name]]))});
    if (current === revision.current) setResult(response);
  }
  return <section className="arena-evidence" aria-label="Policy simulator">
    <h2>Test a policy decision</h2><p>Explore a sample action under the active policy. The labels and approval below are hypothetical; no approval is issued and no tool is run.</p>
    <label>Action<select value={tool} onChange={e=>{revision.current++;setResult(undefined);setTool(e.target.value);}}><option value="send_email">Send email</option><option value="fetch_url">Fetch URL</option></select></label>
    {names.map(name=><fieldset key={name} className="defense-picker"><legend>{labels[name]}</legend>
      <label>{labels[name]} value<input className="policy-value" maxLength={2048} value={items[name].value} onChange={e=>update(name,{value:e.target.value})}/></label>
      <label>{labels[name]} origin<select value={items[name].origin} onChange={e=>update(name,{origin:e.target.value})}><option value="trusted">Trusted</option><option value="untrusted">Untrusted</option></select></label>
      <label><input type="checkbox" checked={items[name].private} onChange={e=>update(name,{private:e.target.checked})}/> Value is private</label>
      <label><input type="checkbox" checked={items[name].sink_allowed} onChange={e=>update(name,{sink_allowed:e.target.checked})}/> Value has permission for this tool</label>
    </fieldset>)}
    <label><input type="checkbox" checked={context} onChange={e=>{revision.current++;setResult(undefined);setContext(e.target.checked);}}/> Untrusted content was read earlier</label>
    <div className="actions"><button disabled={busy || !connection || names.some(name=>!items[name].value)} onClick={()=>action(run)}>Compare policy decisions</button></div>
    {result && <div role="status"><h3>Policy decision comparison</h3>
      <p>Active policy: <code>{result.policy_digest.slice(0,16)}</code> · Mode: {result.policy_mode} · Untrusted context: {result.read_untrusted ? "yes" : "no"}</p>
      <div className="table-scroll"><table><thead><tr><th>Scenario</th><th>Decision</th><th>Why</th><th>Rule</th></tr></thead><tbody>
        {[{name:"Without approval",decision:result.without_approval},{name:"With hypothetical approval",decision:result.with_approval}].map(row=><tr key={row.name}><td>{row.name}</td><td>{row.decision.allowed ? "Allowed" : row.decision.needs_approval ? "Approval required" : "Denied"}</td><td>{explain(row.decision)}</td><td>{row.decision.rule}</td></tr>)}
      </tbody></table></div><p>{result.scope} The labels are selected for this simulation, not evidence of a real action's origin or permissions.</p>
    </div>}
  </section>;
}
