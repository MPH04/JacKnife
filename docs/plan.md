# JacKnife plan

JacKnife is a standalone fuzzing tool. It builds a sanitizer-instrumented
libFuzzer harness for its own packet parser, classifies the crashes with its
own Jac evidence ladder, and publishes a small JSON artifact a later consumer
can fetch. It does not read or modify any other repository.

## Architecture

```
target/jkpacket.c          seeded parser
target/fuzz_jkpacket.c     LLVMFuzzerTestOneInput
scripts/build_fuzzer.sh    clang -fsanitize=fuzzer,address,undefined
scripts/run_fuzzer.sh      timed campaign, crashes kept
scripts/collect_state.py   reproduce, class-preserving minimize, Jac classify
ladder/classify.jac        the only place a label is chosen
dist/artifact/             state.json + manifest.json
scripts/validate_artifact.py
scripts/trigger_and_poll.py
```

GitHub Actions workflow `.github/workflows/fuzz.yml` is `workflow_dispatch`
only. It validates inputs, fuzzes, collects, validates, and uploads a 7-day
artifact. A second job attests the two JSON files. That attest job has not
been executed yet.

## Data flow

1. A caller chooses `run_id`, `duration_seconds`, and `seed`.
2. The workflow copies those values into environment variables. A Python
   process allowlists them and writes the sanitized form to `GITHUB_ENV`.
3. libFuzzer writes `crash-*` files. The collector replays each one under
   ASan/UBSan, keeps one input per sanitizer class and site, and shrinks it
   only when the class stays the same.
4. `ladder/classify.jac` assigns the label. The producer never sets
   `workflow_corroborated`, so the file in the artifact stops at a sanitizer
   label.
5. The consumer's CLI downloads the zip, validates it, checks the GitHub
   Actions run it actually observed, and writes `verified-state.json`. Only
   that derived file can say `Confirmed`.

## Trust boundaries

| Boundary | Untrusted input | What is allowed to trust it |
| --- | --- | --- |
| workflow_dispatch inputs | `run_id`, duration, seed | Only after `validate_workflow_inputs.py` |
| libFuzzer stderr | crash text, addresses, paths | After `escape_untrusted`, then the Jac ladder |
| crash bytes | fuzzer input | Stored as lowercase hex, never executed by the CLI |
| artifact zip | member names, compression, JSON | `validate_artifact.py` rejects before use |
| `classification` field | producer or attacker | Recomputed by the ladder; mismatch rejects |
| promotion flags inside the zip | attacker | Must be false. The validator does not honor them |
| GitHub API run object | only if the token's view matches repo, path, name, sha | `run_corroborates` |
| attestation | `gh attestation verify` | Fail closed until that command succeeds |

## Threat model

The attacker can dispatch the workflow (if they have permission), choose a
hostile `run_id`, and later hand a consumer a crafted zip. They cannot be
allowed to inject shell, escape the artifact directory, or have a simulated
finding labeled `Confirmed`.

JacKnife does not try to stop a person who already has a write token from
replacing the workflow file. Branch protection is the control for that, and
it is not enabled yet. See `docs/repo-settings.md`.

## Target

`jkpacket` is JacKnife's own stateful binary parser. The bugs are documented
in `docs/target.md`. They exist so the sanitizers have a real crash to
report. They are not a claim about any other program.
