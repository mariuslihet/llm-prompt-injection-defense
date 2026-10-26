import React from "react";
import {summarizeEvidence, type EvidenceRow} from "./evaluation";

export default function EvaluationInsights({records}: {records: EvidenceRow[]}) {
  const {outcomes, tools} = summarizeEvidence(records);
  if (!records.length) return null;
  return <section aria-label="Evaluation insights"><h3>Outcome overview · complete run</h3>
    <div className="stats"><article><span>ANSWER TAMPERING</span><strong>{outcomes.integrity}</strong><p>Executions reaching a specified attacker answer target</p></article><article><span>DISCLOSURE</span><strong>{outcomes.disclosure}</strong><p>Executions with an observed confidential marker leak</p></article><article><span>TOOL EFFECTS</span><strong>{outcomes.effects}</strong><p>Executions recording an unauthorized state change</p></article></div>
    <p>Normal-task success: <strong>{outcomes.normalSuccess}/{outcomes.normalTotal}</strong> · Invalid or exhausted executions: <strong>{outcomes.invalid}</strong>. Outcome counts can overlap and include observed harm before a later failure. Missing historical outcome fields are not proof of safety.</p>
    <p>Source-corrected answers: <strong>{outcomes.sourceCorrections}</strong> (normal cases: {outcomes.normalCorrections}) · Answers withheld by source checks: <strong>{outcomes.sourceWithheld}</strong>. Corrections can address ordinary model errors as well as attacks.</p>
    <p>Runs recovered from unusable model replies: <strong>{outcomes.recoveredRuns}</strong> · Model protocol errors: <strong>{outcomes.protocolErrors}</strong>. A recovered program result does not mean the original model response was correct.</p>
    <details><summary>Observed tool usage</summary><div className="table-scroll"><table><thead><tr><th>Tool / source</th><th>Reads or recorded effects</th></tr></thead><tbody>{Object.entries(tools).sort((a,b) => b[1]-a[1]).map(([name,n]) => <tr key={name}><td>{name}</td><td>{n}</td></tr>)}</tbody></table></div><p>Counts come from tool-result events and recorded effects. Rejected model proposals are excluded. Internal summarization is not a state-changing effect.</p></details>
  </section>;
}
