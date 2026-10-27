export type EvidenceRow = {
  case_id?: string; scenario_id?: string; case: string; email: string; payload_sha256: string;
  run: {defense: string; status: string; attack_success: boolean; utility_success: boolean;
    model_calls: number; duration_ms: number; answer: string; model_recoveries?:string[]; model_protocol_errors?:number; outcome_details?: Record<string,unknown>;
    effects: {tool: string}[]; events: {kind: string; details: Record<string,unknown>}[]};
};

export function describeApiError(body: unknown, status: number): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = body.detail;
    if (typeof detail === "string" && detail.trim()) return detail;
    if (Array.isArray(detail)) {
      const messages = detail.map(item =>
        item && typeof item === "object" && typeof item.msg === "string" ? item.msg.replace(/^Value error,\s*/i, "") : ""
      ).filter(Boolean);
      if (messages.length) return messages.join("; ");
    }
  }
  return `Request failed (HTTP ${status}).`;
}

export function describeRunFailure(status: string, code?: string | null): string | null {
  if (status === "budget-exhausted") return "The run ended before completion because its model-call or turn limit was reached.";
  if (code === "provider_error") return "The model provider failed. Check that the configured model is running and reachable.";
  if (code === "source_validation_failed") return "The answer was withheld because required source checks could not be completed.";
  if (status === "error") return "The model response or restricted program could not be validated. Inspect the timeline for details.";
  return null;
}

export function factRows(outcome?: Record<string,unknown>) {
  const expected = outcome?.expected, facts = outcome?.facts, matches = outcome?.matches;
  if (!expected || typeof expected !== "object" || Array.isArray(expected)) return [];
  const actual = facts && typeof facts === "object" && !Array.isArray(facts) ? facts as Record<string,unknown> : {};
  const checks = matches && typeof matches === "object" && !Array.isArray(matches) ? matches as Record<string,unknown> : {};
  return Object.entries(expected).map(([field, value]) => ({
    field, expected: String(value ?? "Unavailable"),
    actual: actual[field] == null ? "Unavailable" : String(actual[field]),
    result: checks[field] === true ? "Matches" : checks[field] === false ? "Differs" : "Unavailable",
  }));
}

export function matchesEvidence(record: EvidenceRow, filter: string): boolean {
  const run = record.run, outcome = run.outcome_details || {};
  const grounding = outcome.grounding as {status?:string} | undefined;
  switch (filter) {
    case "attack": return run.attack_success;
    case "invalid": return ["error","budget-exhausted"].includes(run.status);
    case "normal": return record.case === "benign";
    case "integrity": return outcome.integrity_violation === true;
    case "disclosure": return outcome.confidentiality_violation === true;
    case "effects": return run.effects.length > 0;
    case "utility": return record.case === "benign" && !run.utility_success;
    case "source-corrections": return ["corrected","recovered"].includes(grounding?.status || "");
    case "source-withheld": return grounding?.status === "withheld";
    default: return true;
  }
}

export function summarizeEvidence(records: EvidenceRow[]) {
  const tools: Record<string,number> = {};
  const outcomes = {integrity:0, disclosure:0, effects:0, invalid:0, normalSuccess:0, normalTotal:0, sourceCorrections:0, sourceWithheld:0, normalCorrections:0, recoveredRuns:0, protocolErrors:0};
  for (const r of records) {
    outcomes.recoveredRuns += r.run.model_recoveries?.length ? 1 : 0; outcomes.protocolErrors += r.run.model_protocol_errors || 0;
    for (const key of ["integrity","disclosure","effects","invalid"] as const) {
      if (matchesEvidence(r,key)) outcomes[key]++;
    }
    if (r.case === "benign") { outcomes.normalTotal++; if (r.run.utility_success) outcomes.normalSuccess++; }
    if (matchesEvidence(r,"source-corrections")) {outcomes.sourceCorrections++;if(r.case === "benign") outcomes.normalCorrections++;}
    if (matchesEvidence(r,"source-withheld")) outcomes.sourceWithheld++;
    for (const e of r.run.events) {
      // Count observed tool reads/effects, never merely proposed model actions.
      if (e.kind === "tool-result") {
        const name = String(e.details.tool || e.details.source || "read");
        tools[name] = (tools[name] || 0) + 1;
      }
    }
    for (const effect of r.run.effects) tools[effect.tool] = (tools[effect.tool] || 0) + 1;
  }
  return {outcomes, tools};
}

export function csvCell(value: unknown): string {
  let text = String(value ?? "");
  if (/^[\s\u0000-\u001f]*[=+@-]/u.test(text) || /^[\t\r\n]/u.test(text)) text = "'" + text;
  return '"' + text.replaceAll('"','""') + '"';
}

export function evidenceCsv(records: EvidenceRow[]): string {
  const header = ["case_id","scenario","case","defense","status","attack_objective_reached","task_success","integrity_violation","disclosure","effects","model_calls","duration_ms","input_sha256","input","answer"];
  return [header, ...records.map(r => [r.case_id,r.scenario_id,r.case,r.run.defense,r.run.status,
    r.run.attack_success,r.run.utility_success,r.run.outcome_details?.integrity_violation,
    r.run.outcome_details?.confidentiality_violation,r.run.effects.length,r.run.model_calls,
    r.run.duration_ms,r.payload_sha256,r.email,r.run.answer])]
    .map(row => row.map(csvCell).join(",")).join("\r\n");
}
