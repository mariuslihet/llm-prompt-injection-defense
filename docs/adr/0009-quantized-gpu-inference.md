# ADR 0009: pinned GPU inference for the private MVP

Status: accepted. Date: 2026-10-24.

Hardware inspection found an RTX 2070 with 8 GiB VRAM. Use official Qwen2.5-7B-Instruct
Q4_K_M GGUF weights with official llama.cpp b11853 CUDA 12.4 Windows binaries.
The acquisition script pins model revision and SHA-256 for every downloaded artifact.
This supersedes the 1.5B float32 CPU default in ADR 0008, retaining that adapter for research.

The portable inference service binds only to 127.0.0.1:8081, with one inference slot,
4096-token context and GPU offload. The gateway's llamacpp adapter accepts literal
loopback addresses only and caps each HTTP operation at 120 seconds; jobs retain
their 600-second wall-clock deadline. No Python dependency is added. The runtime
binary is an explicitly pinned deployment dependency for efficient quantized inference.

Model size is not evidence of answer correctness or security. Re-run natural-language
attacks and normal-task tasks, reporting malformed outputs and utility independently.
All model inputs and tools remain local and synthetic. Downloaded weights/binaries
are ignored artifacts; manifests and evaluation evidence are reviewable repository files.
