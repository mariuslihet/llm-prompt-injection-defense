import React, {useEffect, useRef, useState} from "react";

type Inspection = {source:string; decision:string; score:number; reasons:string[]; sanitized_text:string; sanitizer_findings:string[]; scope:string};
type Props = {request:(path:string, body?:unknown)=>Promise<Inspection>; action:(work:()=>Promise<void>)=>Promise<void>; busy:boolean; connection:string};

export const explanations: Record<string,string> = {
  "instruction-override":"The wording resembles an instruction to override other instructions.",
  "authority-claim":"The text contains an authority keyword or a request to forward private content.",
  "fixture-instruction":"A known test instruction or marker was found.",
  "encoding":"The text contains a common encoding or obfuscation indicator.",
  "hidden-content":"The text contains a hidden-content indicator.",
  "approval-bypass":"The text combines approval wording with missing approval; context may be legitimate.",
  "local-classifier":"The configured local classifier contributed to the score.",
  "optional-judge":"The configured judge contributed to the score.",
  "judge-error":"The judge response could not be validated.",
};
export const changes: Record<string,string> = {
  "unicode-normalized":"Invisible or unusual Unicode was normalized.",
  "configured-secret":"A configured secret was redacted.",
  "canary":"A test marker was redacted.",
  "pii-email":"An email address was redacted.",
  "egress-url":"A URL outside the allowlist was removed.",
  "markdown-image":"A Markdown image was removed.",
  "html-escaped":"HTML was converted to plain text.",
};
const decisionText: Record<string,string> = {
  block:"The configured detector would block this text.",
  flag:"The configured detector would flag this text and allow it to continue.",
  shadow:"The detector recorded a shadow finding; it would not block this text.",
  allow:"The detector did not flag this text at its current threshold.",
};

export default function ContentInspection({request,action,busy,connection}: Props) {
  const [source,setSource] = useState("email");
  const [content,setContent] = useState("");
  const [result,setResult] = useState<Inspection>();
  const revision = useRef(0);
  useEffect(() => {revision.current++; setResult(undefined);}, [connection]);
  async function inspect() {
    const requestRevision = ++revision.current;
    setResult(undefined);
    const response = await request("/inspection",{source,content});
    if (revision.current === requestRevision) setResult(response);
  }
  return <section className="arena-evidence" aria-label="Content inspection">
    <h2>Inspect content</h2>
    <p>Check a sample email, page, document or tool response for known indicators and see a sanitized preview. Use sample data only.</p>
    <label>Content source<select value={source} onChange={e=>{revision.current++;setSource(e.target.value);setResult(undefined);}}>
      <option value="email">Email</option><option value="web">Web page</option><option value="document">Document</option><option value="retrieved">Retrieved content</option><option value="tool">Tool output</option><option value="memory">Memory</option><option value="other">Other text</option>
    </select></label>
    <label htmlFor="inspection-content">Text to inspect</label><textarea id="inspection-content" maxLength={32768} value={content} onChange={e=>{revision.current++;setContent(e.target.value);setResult(undefined);}} placeholder="Paste sample content here"/>
    <p>{content.length} / 32,768 characters</p>
    <button disabled={busy || !connection || !content.trim()} onClick={()=>action(inspect)}>Inspect content</button>
    {result && <div role="status"><h3>Inspection result</h3>
      <p><strong>{decisionText[result.decision] || "The detector returned an unknown decision."}</strong></p>
      <p>Source: {result.source} · Indicator score: {result.score.toFixed(2)}. This score is not a probability.</p>
      <h4>Indicators</h4>{result.reasons.length ? <ul>{result.reasons.map(reason=><li key={reason}>{explanations[reason] || reason}</li>)}</ul> : <p>No known indicators were reported.</p>}
      <h4>Sanitized preview</h4><pre className="case-input">{result.sanitized_text || "No text remains after sanitization."}</pre>
      <h4>Preview changes</h4>{result.sanitizer_findings.length ? <ul>{result.sanitizer_findings.map(change=><li key={change}>{changes[change] || change}</li>)}</ul> : <p>No changes were needed.</p>}
      <p>{result.scope} A clean result does not guarantee the content is safe. The source label describes the sample; it does not change the detection rules.</p>
    </div>}
  </section>;
}
