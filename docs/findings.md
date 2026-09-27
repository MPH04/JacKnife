# Evidence ladder

JacKnife's labels are assigned only by `ladder/classify.jac`. Python collects
evidence and asks Jac what the label is. A simulated finding cannot be
promoted, and the generic UBSan token `undefined-behavior` is not a class.

## Rungs

| Label | Required evidence |
| --- | --- |
| `Unknown` | Not enough to call it a crash. Missing or non-hex input, empty report. |
| `Sample` | `simulated` is true. This is the ceiling for a simulated finding, no matter what else is set. |
| `Rejected` | Hostile text, a non-boolean where a flag is required to climb, an oversized string, or `rejected: true`. |
| `Real crash captured` | Lowercase even-length hex input and a non-empty report excerpt. |
| `Reproduced` | Captured, and `reproduced` is the boolean `true`. The integer `1` does not count. |
| `Minimized` | Reproduced, and class-preserving minimization kept an input of the same sanitizer, crash type, and site. |
| `Sanitizer-classified (ASan)` | Minimized, `sanitizer` is `address`, `crash_type` is on the ASan allowlist, and the excerpt contains `ERROR: AddressSanitizer: <crash_type>`. |
| `Sanitizer-classified (UBSan)` | Minimized, `sanitizer` is `undefined`, the crash type is on the UBSan allowlist, and the excerpt contains `UndefinedBehaviorSanitizer`, `runtime error:`, and that type's clang sentence (for example `signed integer overflow`). |
| `Attested` | A sanitizer rung, plus `attestation_verified`, without the two flags required for `Confirmed`. |
| `Confirmed` | A sanitizer rung, a stack trace containing `#0`, `artifact_verified`, and `workflow_corroborated`. |

`Confirmed` means those flags were set by the consumer after it checked the
artifact and the GitHub Actions run. It does not mean the bug is exploitable,
and it does not assign a CVE or a CVSS score. It also does not mean an
attestation was verified. That is `evidence.attestation_verified`.

## Who may set the top flags

The zip produced by the workflow must have `artifact_verified`,
`workflow_corroborated`, and `attestation_verified` all false, and it must
not use the labels `Confirmed` or `Attested`. The validator recomputes the
label with those flags forced off and rejects the zip if the stored label
differs.

`scripts/trigger_and_poll.py` sets `workflow_corroborated` only after
`run_corroborates` accepts the run it polled. It writes that result to
`verified-state.json`, which is not the hashed artifact.

## Allowlists

ASan crash types include `heap-buffer-overflow`, `stack-buffer-overflow`,
`heap-use-after-free`, and the other names listed in `ladder/classify.jac`.

UBSan types are the specific sentences clang prints, mapped in that same
file. `undefined-behavior` is refused.

## Minimized

`scripts/shrink_crash.py` shrinks an input only while the sanitizer, crash
type, and site stay the same. libFuzzer's own minimizer is not used for the
label: on this target it can turn a heap overflow into a different bug that
merely still crashes.
