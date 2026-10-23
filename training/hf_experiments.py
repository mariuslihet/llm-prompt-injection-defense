"""Opt-in local-only HF classifier fine-tuning, activation probes and DPO.

Requires `uv sync --extra research` and pre-downloaded model/tokenizer artifacts.
Never downloads models, never invokes tools and never executes model-generated code.
Each input JSONL must contain fake research data, with split= train/test and a
group identifier so related payloads cannot cross splits.
"""

import argparse
import hashlib
import json
import os
import random
from pathlib import Path


def validate_rows(path: Path) -> list[dict[str, object]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    train = {r["group"] for r in rows if r["split"] == "train"}
    test = {r["group"] for r in rows if r["split"] == "test"}
    calibration = {r["group"] for r in rows if r["split"] == "calibration"}
    if not train or not test or train & test or train & calibration or test & calibration:
        raise ValueError("nonempty disjoint train/test groups required")
    if any(r["split"] not in {"train", "test", "calibration"} for r in rows):
        raise ValueError("unknown split")
    return rows


def run(kind: str, model_path: Path, data: Path, output: Path, seed: int = 42) -> dict[str, object]:
    if not model_path.is_dir() or output.exists():
        raise ValueError("existing local model and fresh output directory required")
    rows = validate_rows(data)
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    import torch
    from transformers import AutoModel, AutoModelForSequenceClassification, AutoTokenizer, set_seed

    set_seed(seed)
    torch.set_num_threads(2)
    torch.use_deterministic_algorithms(True)
    tokenizer = AutoTokenizer.from_pretrained(
        str(model_path), local_files_only=True, trust_remote_code=False
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    output.mkdir(parents=True)
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    metrics: dict[str, object] = {}
    if kind in {"classifier", "probe"}:
        if kind == "classifier":
            model = AutoModelForSequenceClassification.from_pretrained(
                str(model_path),
                num_labels=2,
                local_files_only=True,
                trust_remote_code=False,
                ignore_mismatched_sizes=True,
            )
            model.config.pad_token_id = tokenizer.pad_token_id
            optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5)
        else:
            model = AutoModel.from_pretrained(
                str(model_path), local_files_only=True, trust_remote_code=False
            )
            model.eval()
            # Probe features are generated on fixed fake-data prompts. Labels
            # must describe observed instruction-following, not merely injection presence.
            for parameter in model.parameters():
                parameter.requires_grad = False
            probe = torch.nn.Linear(model.config.hidden_size, 2)
            optimizer = torch.optim.AdamW(probe.parameters(), lr=0.01)

        def logits(row):
            inputs = tokenizer(
                str(row["text"]), return_tensors="pt", truncation=True, max_length=256
            )
            if kind == "classifier":
                return model(**inputs).logits
            with torch.no_grad():
                hidden = model(**inputs).last_hidden_state[:, -1, :].detach()
            return probe(hidden)

        def measure():
            model.eval()
            counts = {"attack_n": 0, "attack_miss": 0, "benign_n": 0, "benign_fp": 0}
            with torch.no_grad():
                for row in test:
                    label = int(row["label"])
                    prediction = int(logits(row).argmax(-1).item())
                    key = "attack" if label else "benign"
                    counts[key + "_n"] += 1
                    counts["attack_miss" if label else "benign_fp"] += prediction != label
            return counts

        metrics["before"] = measure()
        for _ in range(2):
            random.Random(seed + _).shuffle(train)
            if kind == "classifier":
                model.train()
            for row in train:
                optimizer.zero_grad()
                loss = torch.nn.functional.cross_entropy(
                    logits(row), torch.tensor([int(row["label"])])
                )
                loss.backward()
                optimizer.step()
        metrics["after"] = measure()
        if kind == "classifier":
            model.save_pretrained(str(output / "model"))
            tokenizer.save_pretrained(str(output / "model"))
        else:
            torch.save(probe.state_dict(), output / "probe.pt")
    elif kind == "dpo":
        from datasets import Dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM
        from trl import DPOConfig, DPOTrainer

        model = AutoModelForCausalLM.from_pretrained(
            str(model_path), local_files_only=True, trust_remote_code=False
        )
        model.config.pad_token_id = tokenizer.pad_token_id

        def preference_logp(row, completion):
            prefix = tokenizer(
                str(row["prompt"]), return_tensors="pt", truncation=True, max_length=256
            )["input_ids"]
            full = tokenizer(
                str(row["prompt"]) + str(completion),
                return_tensors="pt",
                truncation=True,
                max_length=512,
            )
            labels = full["input_ids"].clone()
            labels[:, : prefix.shape[1]] = -100
            if (labels != -100).sum().item() == 0:
                raise ValueError("empty or truncated preference completion")
            with torch.no_grad():
                return -float(model(**full, labels=labels).loss)

        def preferences():
            model.eval()
            groups = {}
            for suite in ("security", "general"):
                selected = [r for r in test if r.get("suite") == suite]
                if not selected:
                    raise ValueError("DPO test requires security and general capability suites")
                correct = sum(
                    preference_logp(r, r["chosen"]) > preference_logp(r, r["rejected"])
                    for r in selected
                )
                groups[suite] = {"correct_preferences": correct, "n": len(selected)}
            return groups

        metrics["before"] = preferences()
        columns = [{k: str(r[k]) for k in ("prompt", "chosen", "rejected")} for r in train]
        trainer = DPOTrainer(
            model=model,
            args=DPOConfig(
                output_dir=str(output),
                seed=seed,
                num_train_epochs=1,
                per_device_train_batch_size=1,
                report_to="none",
                use_cpu=True,
            ),
            train_dataset=Dataset.from_list(columns),
            processing_class=tokenizer,
            peft_config=LoraConfig(
                r=8, lora_alpha=16, target_modules="all-linear", task_type="CAUSAL_LM"
            ),
        )
        trainer.train()
        model = trainer.model
        metrics["after"] = preferences()
        trainer.save_model(str(output / "model"))
    else:
        raise ValueError("unknown experiment")
    report = {
        "experiment": kind,
        "seed": seed,
        "local_model": str(model_path),
        "data_sha256": hashlib.sha256(data.read_bytes()).hexdigest(),
        "metrics": metrics,
        "limits": "Held-out fixture preferences/classification; not real agent attack ASR.",
    }
    (output / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("classifier", "probe", "dpo"))
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.kind, args.model, args.data, args.output)))


if __name__ == "__main__":
    main()
