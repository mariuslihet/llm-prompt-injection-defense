# ADR 0014: bounded multi-variation workflow suite

Accepted 2026-10-27. Allow the existing business suite to execute either the
selected variation or all five variations in one job. The expanded run uses a
single shared model-call budget and the existing ten-minute deadline. It is
limited to two defenses to bound runtime and evidence size. The default remains
the selected variation so historical requests retain their behavior.

The dataset fingerprint includes the coverage choice; when all variations run,
the individual variation selector does not affect the input set. Each row keeps
its case ID, input hash, actual execution, source checks and expected-fact
comparison. The UI never infers missing comparisons. Generated adaptive attacks
remain a separate campaign; this change does not claim broad agent compatibility
or independent validation. No dependencies or external tool capabilities added.
