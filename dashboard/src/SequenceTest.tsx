import React, {useEffect, useRef, useState} from "react";

type Step = {index:number; op:string; tool?:string|null; decision?:{allowed:boolean; rule:string; reason:string; needs_approval:boolean}};
type Sequence = {variant:string; planned_instructions:number; trace:{policy_digest:string; steps:Step[]; effect_count:number; halted_at:number|null; skipped_instructions:number}; simulated_effects:{tool:string;text:string}[]; scope:string};
type Props = {request:(path:string,body?:unknown)=>Promise<Sequence>; action:(work:()=>Promise<void>)=>Promise<void>; busy:boolean; connection:string};

export default function SequenceTest({request,action,busy,connection}:Props) {
  const [variant,setVariant] = useState("deny_first");
  const [document,setDocument] = useState("Sample report for review.");
  const [result,setResult] = useState<Sequence>();
  const revision=useRef(0);
  useEffect(()=>{revision.current++;setResult(undefined);},[connection]);
  async function run() {
    const current=++revision.current; setResult(undefined);
    const response=await request("/ifc/sequence-test",{variant,document});
    if (revision.current === current) setResult(response);
  }
  return <section className="arena-evidence" aria-label="Multi-step policy test">
    <h2>Test a multi-step action</h2>
    <p>See how the interpreter handles a denied email action and the instructions after it. The sequence uses sample text and simulated tools.</p>
    <label>Sequence<select value={variant} onChange={e=>{revision.current++;setResult(undefined);setVariant(e.target.value);}}>
      <option value="deny_first">Denied action first, then summarize</option><option value="allow_then_deny">Summarize first, then denied action, then summarize</option>
    </select></label>
    <label htmlFor="sequence-document">Sample document</label><textarea className="short-text" id="sequence-document" maxLength={4096} value={document} onChange={e=>{revision.current++;setResult(undefined);setDocument(e.target.value);}}/>
    <button disabled={busy || !connection || !document.trim()} onClick={()=>action(run)}>Run multi-step test</button>
    {result && <div role="status"><h3>Execution result</h3>
      <p>Planned: {result.planned_instructions} instructions · Processed: {result.trace.steps.length} · Skipped after denial: <strong>{result.trace.skipped_instructions}</strong> · Recorded sample actions: {result.trace.effect_count}</p>
      <p>Policy: <code>{result.trace.policy_digest.slice(0,16)}</code> · {result.trace.halted_at === null ? "No denial recorded" : `Stopped at step ${result.trace.halted_at+1}`}</p>
      <ol>{result.trace.steps.map(step=><li key={step.index}>Step {step.index+1}: {step.tool || step.op} · {step.decision ? `${step.decision.allowed ? "Allowed" : "Denied"}: ${step.decision.reason}` : "Completed"}</li>)}</ol>
      {result.simulated_effects.length > 0 && <details><summary>Earlier sample actions</summary>{result.simulated_effects.map((effect,index)=><p key={index}>{effect.tool}: {effect.text}</p>)}</details>}
      <p>{result.scope} The trace describes this fixed test, not arbitrary external tools.</p>
    </div>}
  </section>;
}
