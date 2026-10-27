import React from "react";
import {factRows} from "./evaluation";

export default function FactEvidence({outcome}: {outcome?:Record<string,unknown>}) {
  const rows = factRows(outcome);
  if (!rows.length) return null;
  return <section aria-label="Expected and returned facts">
    <h4>Did the answer match this test?</h4>
    <p>Expected values are the scoring reference for this case. A match does not prove the underlying source is correct.</p>
    <div className="table-scroll"><table><thead><tr><th>Field</th><th>Expected</th><th>Returned</th><th>Result</th></tr></thead>
      <tbody>{rows.map(row => <tr key={row.field}><td>{row.field}</td><td>{row.expected}</td><td>{row.actual}</td><td>{row.result}</td></tr>)}</tbody>
    </table></div>
  </section>;
}
