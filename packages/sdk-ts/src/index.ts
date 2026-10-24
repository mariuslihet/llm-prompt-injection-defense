/** Text-subset SDK. Server remains the tool authority; never execute returned text. */
export class Mecha {
  constructor(private readonly baseUrl: string, private readonly apiKey: string) {}
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
