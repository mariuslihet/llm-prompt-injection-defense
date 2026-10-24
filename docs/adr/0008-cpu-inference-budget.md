# ADR 0008: explicit local CPU precision and generation limits

Date: 2026-10-24. Status: accepted after failed quantization experiments.

The installed Intel i7-8700 does not accelerate the checkpoint's bfloat16 dtype.
The local adapter explicitly converts weights/activations to float32 on CPU and
records local_precision in reports. Dynamic int8 was investigated: oneDNN
requires float32 inputs and the pinned Windows torch build does not support
FBGEMM. The attempted quantization path was removed rather than silently falling
back or shipping an unverified default. No new dependency was added.

Each generation permits at most 192 new tokens and 60 seconds, within a
600-second job. Truncated/malformed outputs remain invalid; bounded schema
recovery consumes target turns. These cooperative limits do not provide hard
process isolation or production inference throughput guarantees. Quantization
is a negative experimental result, not a supported runtime option.
