# JacKnife API contract

This document is the interface. A consumer can trigger a run, poll it,
download the artifact, and interpret `state.json` without reading the
implementation. The repository is `MPH04/JacKnife`. JacKnife is not part of
JacBox.

Nothing here is a CVE, a CVSS score, or a statement that a bug is exploitable.

## What you get

A workflow run uploads one artifact named `jacknife-<run_id>`. The zip
contains exactly two files:

- `state.json` — findings and run metadata
- `manifest.json` — repo, workflow, tool versions, and the sha256 of `state.json`

Retention is 7 days. The zip is the hashed artifact. The CLI also writes
`verified-state.json` next to it after it has checked GitHub. That second
file is derived. It is not inside the zip and it is not covered by
`manifest.file_hashes`.

## Labels

Allowed `classification` values:

- `Sample`
- `Real crash captured`
- `Reproduced`
- `Minimized`
- `Sanitizer-classified (ASan)`
- `Sanitizer-classified (UBSan)`
- `Attested`
- `Confirmed`
- `Rejected`
- `Unknown`

Inside the downloaded zip, a finding stops at a sanitizer label (or lower).
`Confirmed` and `Attested` are rejected if they appear in the zip. They can
appear in `verified-state.json` after the CLI checks the run.

`Confirmed` means all of the following were true together:

- the input is lowercase hex
- the crash was reproduced and minimized without changing sanitizer class,
  crash type, or site
- the report matches a recognized ASan or UBSan class (see `docs/findings.md`)
- the stack trace contains a `#0` frame
- the zip passed schema, hash, repo, and workflow checks
- the CLI observed a completed, successful `workflow_dispatch` of
  `.github/workflows/fuzz.yml` on `MPH04/JacKnife` whose run name was
  `fuzz-<run_id>`, whose `head_sha` matches `commit_sha`, and whose artifact
  name was `jacknife-<run_id>`

`Confirmed` does not mean an attestation was checked. Read
`corroboration.attestation` in `verified-state.json`. Until a human runs
`scripts/verify_attestation.py` against a real bundle, that field is
`not-checked`.

## state.json

UTF-8 JSON, no BOM, no duplicate keys. Unknown fields are invalid.
`schema_version` is the string `"1"`.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | `"1"` |
| `generator` | string | `"jacknife"` |
| `run_id` | string | The dispatch input, `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` |
| `run_date` | string | UTC time the file was built, `YYYY-MM-DDThh:mm:ssZ` |
| `source` | string | `"github-actions"` or `"local"` |
| `workflow_url` | string or null | `https://github.com/MPH04/JacKnife/actions/runs/<id>` or null for a local run |
| `commit_sha` | string or null | 40 lowercase hex. Null when the producer tree was dirty |
| `duration_seconds` | int | 1–300 |
| `seed` | int | 0–4294967295 |
| `crash_files_seen` | int | How many `crash-*` files the campaign directory contained |
| `findings` | array | At most 64 findings, unique `finding_id` |

Each finding:

| Field | Type | Meaning |
| --- | --- | --- |
| `finding_id` | string | 16 lowercase hex. sha256 of `sanitizer\|crash_type\|site`, truncated. Not a secret |
| `classification` | string | One label from the list above |
| `sanitizer` | string | `"address"`, `"undefined"`, or `""` |
| `crash_type` | string | Sanitizer class such as `heap-buffer-overflow` or `signed-integer-overflow`. Empty if none |
| `input_hex` | string | Lowercase hex of the crash input. Even length, 2–16384 characters. This is the only form of the input |
| `stack_trace` | string | Escaped sanitizer excerpt. Control characters, ANSI, HTML metacharacters, and bidi marks are stored as the six characters `\uXXXX` |
| `reproducible` | bool | Same value as `evidence.reproduced` |
| `minimized` | bool | Same value as `evidence.minimized` |
| `site` | string | C function in `jkpacket.c` where the report placed the bug, or `""` |
| `evidence` | object | Flags below |

`evidence` fields are all booleans except `report_excerpt` (string, same escaping as `stack_trace`):

- `simulated` — true only for a synthetic sample. Never true in a workflow artifact
- `rejected`
- `reproduced`
- `minimized`
- `artifact_verified` — must be false in the zip
- `workflow_corroborated` — must be false in the zip
- `attestation_verified` — must be false in the zip
- `report_excerpt`

Booleans are JSON `true` / `false` only. The number `1` is invalid.

## manifest.json

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | `"1"` |
| `repo` | string | Must be `MPH04/JacKnife` |
| `workflow` | string | Must be `fuzz.yml` |
| `run_id` | string | Same as `state.json` |
| `github_run_id` | int or null | Numeric Actions run id. Required when `source` is `github-actions`, and must match `workflow_url` |
| `commit_sha` | string or null | Same as `state.json` |
| `source` | string | Same as `state.json` |
| `run_date` | string | Same as `state.json` |
| `tool_versions` | object | Strings `clang`, `python`, `jaclang`, `libfuzzer` |
| `file_hashes` | object | `state.json` → `sha256:<64 lowercase hex>` of the exact `state.json` bytes |
| `duration_seconds` | int | Same as `state.json` |
| `seed` | int | Same as `state.json` |
| `target_hashes` | object | sha256 of `target/jkpacket.c`, `target/jkpacket.h`, `target/fuzz_jkpacket.c` |
| `crash_files_seen` | int | Same as `state.json` |

Reject the artifact if any hash, repo, workflow, or shared field disagrees.

## verified-state.json

Same fields as `state.json`, plus:

| Field | Type | Meaning |
| --- | --- | --- |
| `corroboration.method` | string | `"github-api"` |
| `corroboration.github_run_id` | int | Run the CLI polled |
| `corroboration.run_name` | string | `fuzz-<run_id>` |
| `corroboration.head_sha` | string | SHA GitHub reported |
| `corroboration.artifact_name` | string | `jacknife-<run_id>` |
| `corroboration.observed_at` | string | When the CLI wrote the file |
| `corroboration.attestation` | string | `not-checked`, `verified`, `failed`, or `absent` |

Finding labels in this file are recomputed with `artifact_verified` and
`workflow_corroborated` set. A zip that merely claims those flags is rejected
rather than promoted.

## Trigger

The workflow must be on the default branch before GitHub will dispatch it.
This file ships on a branch first; dispatch works after it is merged to `main`.

```bash
export JACKNIFE_GITHUB_TOKEN="..."   # repo scope sufficient to dispatch and read Actions artifacts
python3 scripts/trigger_and_poll.py --repo MPH04/JacKnife \
    --run-id "$(uuidgen)" --duration 90 --seed 1 --out-zip run.zip
```

The token is the environment variable `JACKNIFE_GITHUB_TOKEN` only. The CLI
exits 2 if you pass `--token`. It does not print the token. On success it
writes `run.zip` and `verified-state.json` in the zip's directory.

What the CLI does:

1. `POST /repos/MPH04/JacKnife/actions/workflows/fuzz.yml/dispatches` with `ref=main` and string inputs `run_id`, `duration_seconds`, `seed`. A 204 is success. The body does not contain a run id.
2. Poll `GET /repos/MPH04/JacKnife/actions/workflows/fuzz.yml/runs?event=workflow_dispatch&per_page=20` every 15 seconds, at most 80 times.
3. Accept a run only when `name` is `fuzz-<run_id>`, `path` is `.github/workflows/fuzz.yml`, and `created_at` is not earlier than the dispatch by more than 30 seconds. Two matches is an error.
4. Require `status=completed` and `conclusion=success`.
5. Download the single artifact named `jacknife-<run_id>`. Redirects are followed only to GitHub and GitHub artifact storage hosts. The signed redirect URL is not logged.
6. Run `scripts/validate_artifact.py` rules on the zip. Then corroborate the run (`head_sha`, html URL, workflow path, conclusion) and write `verified-state.json`.

## Validate without dispatching

```bash
python3 scripts/validate_artifact.py --zip run.zip
python3 scripts/validate_artifact.py --dir fallback --check-targets
```

Exit 0 means the artifact is internally consistent and every label matches the
ladder with promotion flags forced off. Exit 1 means rejected. A rejected
artifact must not be parsed by the consumer.

## Attestation

```bash
export JACKNIFE_GITHUB_TOKEN="..."
python3 scripts/verify_attestation.py --repo MPH04/JacKnife --artifact downloaded/state.json
```

The script shells out to `gh attestation verify --repo MPH04/JacKnife`. Missing
`gh`, a bad status, or success text that does not contain "verified" is a
failure. Not verified: this command against a bundle from a real run.

## Local fallback

`fallback/state.json` and `fallback/manifest.json` are a real local campaign,
not a GitHub run. Labels stop at the sanitizer rung. `source` is `local` and
`workflow_url` is null. Use it when GitHub is unreachable. Do not treat it as
`Confirmed`.

```bash
python3 scripts/validate_artifact.py --dir fallback --check-targets
```

## Rebuild the fuzzer

```bash
bash scripts/install_toolchain.sh
bash scripts/build_fuzzer.sh
JACKNIFE_DURATION=90 JACKNIFE_SEED=1 JACKNIFE_CRASH_DIR=runs/crashes bash scripts/run_fuzzer.sh
python3 scripts/collect_state.py --crash-dir runs/crashes --out-dir dist/artifact --source local --run-id local --duration 90 --seed 1
python3 scripts/validate_artifact.py --dir dist/artifact --check-targets
```
