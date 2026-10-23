# ADR 0003: Separate runnable infrastructure from experimental evidence

Accepted. Research dependencies are optional and pinned; no pretrained weight
downloads occur implicitly. HF experiments accept only explicit local paths,
disable remote code and network access, seed training and require disjoint
groups. The cheap Naive Bayes self-play experiment is an additional diagnostic,
not a substitute for the requested fine-tuned transformer/probe/DPO experiments.
Dependencies torch/transformers/PEFT/TRL implement the requested model research;
datasets supplies TRL's typed local training records. OpenTelemetry exporters
and psycopg are optional so the default offline install stays small.

Deployment assets default to one worker and mock providers. Policy revisions,
arena review payloads and grants are process-local; they are not a durable
distributed product. Do not expose this prototype as a public arena. Docker
base images are pinned by registry-resolved digest. That controls content
identity but does not certify image safety or runtime isolation.

No remote exists for this repository. A GitHub workflow cannot run or attest
artifacts locally, and a release cannot be published without its destination.
The final report must preserve these external acceptance blockers explicitly.
