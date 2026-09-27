# Research notes

Each note is a decision, not a dump of the source. "Not verified" means this
environment did not execute that check.

## libFuzzer campaign flags

- Decision: run `clang -fsanitize=fuzzer,address,undefined` and campaign with `-fork=1 -ignore_crashes=1 -max_total_time`.
- Source: LLVM libFuzzer manual, https://llvm.org/docs/LibFuzzer.html (flags `-fork`, `-ignore_crashes`, `-max_total_time`, `-minimize_crash`, `-runs`).
- What it says: fork mode and `-ignore_crashes` keep fuzzing after a crash; passing a file with `-runs=1` executes that input instead of mutating it; `-minimize_crash=1` shrinks the first input while it still crashes.
- How JacKnife applies it: `scripts/run_fuzzer.sh` and `scripts/reproduce_crash.sh`. Minimization for labels does **not** use `-minimize_crash`, because on this target that mode can change the sanitizer class. See the local observation below.
- Local observation: a clang 18 parent process exited 134 after a timed run that had already saved `crash-*` files. The wrapper treats that as a finished campaign when crash files exist.
- Not verified: that every libFuzzer version exits 134 the same way. Required verification: read the exit status on the GitHub-hosted runner.

## Sanitizer classes

- Decision: trust `ERROR: AddressSanitizer: <class>` and the UBSan `runtime error:` sentence. Do not trust SUMMARY's `undefined-behavior` token.
- Source: AddressSanitizer documentation, https://clang.llvm.org/docs/AddressSanitizer.html ; UndefinedBehaviorSanitizer documentation, https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html .
- What they say: ASan names the error (`heap-buffer-overflow`, `stack-buffer-overflow`, `heap-use-after-free`, and others). UBSan prints a runtime error sentence and can abort when recovery is disabled.
- How JacKnife applies it: `-fno-sanitize-recover=undefined` is in the build. `scripts/reports.py` maps the sentence `signed integer overflow` to `signed-integer-overflow`. The Jac allowlist rejects the generic token.
- Local observation: clang 18.1.3 printed `SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior target/jkpacket.c:77:34` for a real `signed integer overflow` in `bug_scale_add`.

## Workflow input injection

- Decision: pass `workflow_dispatch` inputs only through environment variables, then allowlist them in Python before `GITHUB_ENV` / `GITHUB_OUTPUT`.
- Source: GitHub "Secure use reference", https://docs.github.com/en/actions/reference/security/secure-use (section "Use an intermediate environment variable").
- What it says: putting untrusted `${{ }}` data directly in a `run:` script is script injection. Assigning it to an env var stores the value in memory instead of splicing it into the generated shell.
- How JacKnife applies it: `.github/workflows/fuzz.yml` uses the env-var pattern. `run-name` still contains `${{ inputs.run_id }}` because that is the discoverability requirement. GitHub does not re-parse that string as an expression. The value can still make a confusing display name; the shell never sees it.
- Not verified: a live dispatch with a quote-bearing run id. Required verification: dispatch with `run_id` set to a value the validator rejects and confirm the job fails in the validate step without executing the fuzzer. The validator itself rejects that value locally.

## Permissions, pinning, attestations

- Decision: `permissions: {}` on the workflow, per-job grants, actions pinned to full commit SHAs, attestation in a separate job.
- Source: the same Secure use reference (least-privilege `GITHUB_TOKEN`, pin third-party actions to a full SHA). Artifact attestation action inputs were read from `actions/attest-build-provenance` `action.yml` at commit `4d101475d8b20a2381f78447822ac1eab6504dd8`.
- Pins recorded on 2026-09-27 from the GitHub Git API:
  - `actions/checkout` v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1`
  - `actions/upload-artifact` v7.0.1 `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`
  - `actions/download-artifact` v8.0.1 `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c`
  - `actions/attest-build-provenance` v4.2.2 `4d101475d8b20a2381f78447822ac1eab6504dd8` (it calls `actions/attest` at `508db95dd578ae2727ebd6217d5ba78e4fbda05d`, pinned by upstream)
- How JacKnife applies it: the fuzz job gets `contents: read` and `actions: write`. The attest job gets `actions: read`, `contents: read`, `id-token: write`, and `attestations: write`. No cache action is used.
- Not verified: a real attestation. Required verification: after the workflow is on `main`, dispatch it and run `gh attestation verify downloaded/state.json --repo MPH04/JacKnife`.

## workflow_dispatch has no run id in the response

- Decision: find the run by `run-name` `fuzz-<run_id>`, then require path, event, head SHA, and html URL before calling it corroborated.
- Source: GitHub REST "Create a workflow dispatch event" returns 204 No Content with an empty body. The run object is available from "List workflow runs".
- How JacKnife applies it: `scripts/trigger_and_poll.py` polls `GET /repos/MPH04/JacKnife/actions/workflows/fuzz.yml/runs?event=workflow_dispatch` and accepts only one name match created after the dispatch.
- Not verified: a live 204 from this token. Required verification: the exact command in `docs/api-contract.md` once the workflow file is on `main`. Dispatch only works for a workflow file that exists on the default branch.

## OpenSSF Scorecard and dangerous workflows

- Decision: no `pull_request_target`, no unpinned actions, no untrusted checkout.
- Source: Secure use reference, which points at OpenSSF Scorecard's Dangerous-Workflow check and the hardening guide.
- How JacKnife applies it: the only trigger is `workflow_dispatch`. Scorecard's Branch-Protection and Token-Permissions checks will stay red until an owner applies `docs/repo-settings.md`.
- Not verified: a Scorecard run. Required verification: `scorecard --repo=github.com/MPH04/JacKnife`.

## ClusterFuzzLite

- Decision: do not adopt ClusterFuzzLite. Use one dispatch workflow.
- Source: ClusterFuzzLite describes CI fuzzing with sanitizers and crash replay. It is a reference for the shape of a CI fuzz job, not a dependency.
- How JacKnife applies it: own harness, own corpus, own artifact schema.

## Zip slip and compression bombs

- Decision: never call `extract` or `extractall`. Reject any member that is not exactly `state.json` or `manifest.json`, reject symlinks, absolute names, `..`, duplicates, and compression ratios above 50:1.
- Source: Snyk's Zip Slip advisory (archive entry names containing `../` are written outside the destination if the extractor concatenates paths).
- How JacKnife applies it: `scripts/validate_artifact.py` reads members by the checked name only.

## Jac as the ladder

- Decision: classification lives in Jac (`jaclang==0.9.11`, hash pinned).
- Source: Jac language docs, https://docs.jaseci.org/tutorials/language/basics/ . `report` is a reserved word, so the ladder uses the name `excerpt`. `len()` in this Jac version does not accept `str`; the ladder counts characters itself.
- Local observation: `jac check ladder/classify.jac` passed on jaclang 0.9.11, and `jac run` returned the expected labels for the case list in the unit tests.
