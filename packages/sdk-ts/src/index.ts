/** Source labels describe the input; they do not change its trust or the inspection rules. */
export type InspectionSource = "email" | "web" | "document" | "retrieved" | "tool" | "memory" | "other";
export type InspectionResult = {
  source: InspectionSource; decision: "allow" | "block" | "flag" | "shadow"; score: number;
  reasons: string[]; sanitized_text: string; sanitizer_findings: string[]; scope: string;
};

function validInspection(value: unknown): value is InspectionResult {
  if (!value || typeof value !== "object") return false;
  const row = value as Record<string,unknown>;
  return typeof row.source === "string" && ["email","web","document","retrieved","tool","memory","other"].includes(row.source)
    && typeof row.decision === "string" && ["allow","block","flag","shadow"].includes(row.decision)
    && typeof row.score === "number" && Number.isFinite(row.score) && row.score >= 0 && row.score <= 1
    && Array.isArray(row.reasons) && row.reasons.every(item => typeof item === "string")
    && typeof row.sanitized_text === "string" && Array.isArray(row.sanitizer_findings)
    && row.sanitizer_findings.every(item => typeof item === "string") && typeof row.scope === "string";
}

/** Text-subset SDK. Server remains the tool authority; never execute returned text. */
export class Mecha {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  constructor(baseUrl: string, apiKey: string) { this.baseUrl = baseUrl; this.apiKey = apiKey; }
  /** Inspect sample text. A clean result does not authorize an agent or a tool call. */
  async inspect(content: string, source: InspectionSource = "other"): Promise<InspectionResult> {
    const response = await fetch(`${this.baseUrl.replace(/\/$/, "")}/inspection`, {
      method: "POST", redirect: "error", headers: {Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json"},
      body: JSON.stringify({source, content})
    });
    if (!response.ok) throw new Error(`Mecha inspection failed (${response.status})`);
    const value: unknown = await response.json();
    if (!validInspection(value) || value.source !== source) throw new Error("Invalid Mecha inspection response");
    return value;
  }
  async startAgent(email: string, defense = "full-ifc", campaign = false, idempotencyKey = crypto.randomUUID()): Promise<unknown> {
    const response = await fetch(`${this.baseUrl.replace(/\/$/, "")}/lab/jobs`, {
      method: "POST", redirect: "error", headers: {Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json", "Idempotency-Key": idempotencyKey},
      body: JSON.stringify({kind: campaign ? "campaign" : "agent", email, defense})
    });
    if (!response.ok) throw new Error(`Mecha job request failed (${response.status})`);
    return response.json();
  }
  async job(identity: string): Promise<unknown> {
    if (!/^[a-zA-Z0-9]{32}$/.test(identity)) throw new Error("Invalid job ID");
    const response = await fetch(`${this.baseUrl.replace(/\/$/, "")}/lab/jobs/${identity}`, {
      redirect: "error", headers: {Authorization: `Bearer ${this.apiKey}`}
    });
    if (!response.ok) throw new Error(`Mecha job request failed (${response.status})`);
    return response.json();
  }
  async complete(content: string, model = "mecha-mock"): Promise<string> {
    const response = await fetch(`${this.baseUrl.replace(/\/$/, "")}/v1/chat/completions`, {
      method: "POST", redirect: "error", headers: {
        "Authorization": `Bearer ${this.apiKey}`, "Content-Type": "application/json"
      }, body: JSON.stringify({ model, messages: [{ role: "user", content }] })
    });
    if (!response.ok) throw new Error(`Mecha request failed (${response.status})`);
    const value = await response.json();
    if (typeof value?.choices?.[0]?.message?.content !== "string") throw new Error("Invalid gateway response");
    return value.choices[0].message.content;
  }
}
