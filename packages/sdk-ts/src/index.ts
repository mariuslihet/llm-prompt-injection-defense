/** Text-subset SDK. Server remains the tool authority; never execute returned text. */
export class Mecha {
  constructor(private readonly baseUrl: string, private readonly apiKey: string) {}
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
