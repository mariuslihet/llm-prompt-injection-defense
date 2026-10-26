import React from "react";

type Check = {field:string; proposed:string; source_value:string; matched:boolean; sources:string[]; rule:string};
type Evidence = {mode:string; status:string; reason?:string; checks:Check[]};

export default function GroundingEvidence({outcome}: {outcome?:Record<string,unknown>}) {
  const evidence = outcome?.grounding as Evidence | undefined;
  if (!evidence || ["off","not-applied"].includes(evidence.status)) return null;
  return <section aria-label="Source answer verification" className="source-verification">
    <h4>Answer checked against source records</h4>
    <p>{evidence.status === "corrected" ? "The model proposed different facts. The returned answer uses the configured source fields and rules shown below."
      : evidence.status === "recovered" ? "The model reply could not be used. The returned answer was reconstructed from validated source records using the configured rules."
      : evidence.status === "matched" ? "The proposed facts agree with the configured source fields and rules."
      : evidence.status === "withheld" ? "No answer was released because the required source checks failed."
      : evidence.status === "differences-found" ? "Shadow mode found differences. The proposed answer was left unchanged."
      : evidence.status === "not-covered" ? "This task has no configured structured-source resolver. No source-integrity claim applies."
      : "Source checks were unavailable in shadow mode. The proposed answer was left unchanged."}</p>
    <p>Mode: {evidence.mode} · Result: {evidence.status}{evidence.reason && <> · {evidence.reason}</>}</p>
    {!!evidence.checks?.length && <div className="table-scroll"><table><thead><tr><th>Field</th><th>Model proposed</th><th>Source / rule result</th><th>Check</th><th>Source and rule</th></tr></thead><tbody>{evidence.checks.map(c => <tr key={c.field}><td>{c.field}</td><td>{c.proposed}</td><td>{c.source_value}</td><td>{c.matched ? "Agrees" : evidence.mode === "enforce" ? "Corrected" : "Differs"}</td><td>{c.sources.join(" + ")}<br/>{c.rule}</td></tr>)}</tbody></table></div>}
    <p>Agreement with configured records does not verify the underlying source's truth. Original proposals remain in the execution trace.</p>
  </section>;
}
