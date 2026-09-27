# Security report

Attacks against JacKnife's own pipeline. No third-party target was used.
Retest command: `python3 -m unittest discover -s tests -v` on 2026-09-27, 36 tests, all passed.
The four seeded parser bugs were also replayed under clang 18.1.3 and matched
`heap-buffer-overflow`, `stack-buffer-overflow`, `heap-use-after-free`, and
`signed integer overflow`.

| Attack | Target | Input | Expected failure | Actual result | Severity | Fix | Retest | Remaining risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Zip slip | `validate_artifact.py` | Member `../evil` | Reject the zip | `ArtifactRejected` | high | Only `state.json` and `manifest.json` are legal names. Members are read by name, never extracted | `test_zip_slip_symlink_and_absolute_names_are_rejected` | A new archive format is out of scope |
| Absolute path and symlink members | same | `/etc/passwd`, mode `0120777` | Reject | Rejected | high | Name check plus Unix mode symlink check | same test | None for zip members |
| Directory symlink | directory mode | `state.json` → `/etc/passwd` | Reject | Rejected | medium | `read_dir` refuses symlinks | `test_directory_symlink_is_rejected` | None found |
| Compression bomb | zip | 2 MiB of repeated bytes | Reject | Rejected (size and ratio limits) | medium | 1 MiB per file, 5 MiB zip, ratio 50 | `test_compression_bomb_is_rejected` | A bomb just under every limit still costs a read. The caps are the bound |
| Duplicate JSON keys | `state.json` | `{"a":1,"a":2}` | Reject | Rejected | medium | `object_pairs_hook` refuses a repeated key | `test_duplicate_keys_and_confirmed_claim_are_rejected` | None found |
| Forged `Confirmed` | zip `classification` | Label set to `Confirmed` with producer flags | Reject | Rejected by the closed schema | high | Zip cannot carry `Confirmed` or `Attested` | same test | A separate `verified-state.json` is not hash-bound. Treat it as CLI output, not as the artifact |
| Self-promotion flag | `evidence.workflow_corroborated` | `true` inside the zip | Reject | Rejected | high | Producer artifacts must keep promotion flags false. The validator does not copy them into the ladder | `test_promotion_flag_inside_zip_is_rejected` | The CLI must stay the only writer of that flag |
| Hash mismatch | `manifest.file_hashes` | Wrong sha256 | Reject | Rejected | high | Recomputed hash of the exact `state.json` bytes | `test_hash_mismatch_wrong_repo_and_hostile_text` | None found |
| Wrong repo | `manifest.repo` | `evil/other` | Reject | Rejected | high | Repo is fixed to `MPH04/JacKnife` | same test | None found |
| Wrong workflow / stale run | corroboration | path `.github/workflows/evil.yml`, bad html URL, failed conclusion | Do not corroborate | `run_corroborates` returns false | high | Name, path, event, head SHA, conclusion, and html URL must all match | `test_corroboration_rules` | Not verified against a live GitHub run |
| Workflow input injection | dispatch inputs | newline in `run_id`, `90\nEVIL=1`, shell quotes, other repo, other server | Reject before fuzzing | Non-zero, and the injected text is not copied to stdout | high | Allowlist after the env-var boundary. No `run:` step interpolates inputs | `InputTests` | `run-name` still displays the raw input. It is not a shell |
| HTML, ANSI, bidi in crash text | stack trace | ESC, `<script>`, U+202E, and a JSON `\u202e` | Neutralize, then reject raw forms | Stored form is `\uXXXX`. Raw forms fail validation | medium | `escape_untrusted` plus `has_hostile` | `test_escape_neutralizes_ansi_html_and_bidi`, `test_json_unicode_bidi_is_hostile_after_decode` | A consumer that un-escapes and prints the result can undo this. The contract says not to |
| Token on the command line | CLI | `--token secret` | Exit 2, do not log it | Exit 2, secret absent from output | high | Rejected before argparse | `test_cli_refuses_token_argument_and_other_repos` | A token in the environment is still visible in `/proc` to the same user |
| Token echoed by an API error | transport | Error body containing the token | Redact | Exception text has `[redacted]` | medium | `redact()` on `ApiError` | `test_trigger_redacts_token_and_rejects_bad_redirect_host` | Not verified against a real GitHub error page |
| Off-allowlist download host | transport | `https://evil.example`, `http://api.github.com` | Refuse | `ApiError` before any use | high | HTTPS and a host suffix allowlist. Auth header is not forwarded off `api.github.com` | `test_host_allowlist` | A future GitHub host fails closed until the list is updated |
| Poll flood | CLI loop | — | Bounded polls | 80 polls, 15 s apart, hard-coded | low | Constants `MAX_POLLS` and `POLL_SECONDS` | Code inspection. No live poll | A caller can still run many processes |
| Quiet attestation success | `verify_attestation.py` | fake `gh` exit 0 with no output; missing `gh`; exit 1 | Fail closed | All three return 1 | medium | Require the word `verified` in gh output | `AttestationTests` | Not verified: `gh attestation verify` on a real bundle |
| Simulated finding | ladder | every confirm flag true, `simulated: true` | Stay at `Sample` | `Sample` | high | Jac returns `Sample` before any rung | `test_simulated_cannot_be_confirmed` | None for this case |
| Generic UBSan token | ladder | crash type `undefined-behavior` | Do not sanitize-classify | `Minimized` | medium | Allowlist uses the runtime-error sentence | `test_generic_ubsan_token_is_not_a_class` | None for this token |
| Integer pretending to be a bool | ladder | `reproduced: 1` | Do not climb | `Real crash captured` | medium | Jac requires `type(value) == bool` | `test_integer_is_not_a_bool` | None found |
| libFuzzer minimizer changes the bug | shrinker | heap seed minimized by libFuzzer became a stack overflow (18 bytes) | Do not label that input as the heap bug | Class-preserving shrinker keeps heap-buffer-overflow and shrinks 73→26 | high | `shrink_crash.py` replays every candidate | Local shrink of all four seeds; fallback findings are minimized and class-stable | Minimizer is not a general superoptimizer. Some inputs stay large |
| Corpus pollution | `run_fuzzer.sh` | libFuzzer's first corpus dir | Do not rewrite `target/corpus` | A 3 second run had filled it with hash-named inputs. The script now fuzzes a copy under `runs/corpus` | medium | Copy `seed_*.bin` before the campaign | Manual 3 second rerun left the five seeds in place | Pointing libFuzzer at `target/corpus` by hand still writes there |

## Extra attacks beyond the required list

1. Duplicate JSON keys (above).
2. Producer zip setting `workflow_corroborated` itself (above).
3. `gh` exiting 0 without saying verified (above).
4. JSON unicode escape of a bidi mark, which decodes to the real character and is then rejected.
5. Download host `github.com.evil.test` and `api.github.com.attacker.test`, which the suffix check does not allow.

## Not attacked here

- A live `workflow_dispatch` (the workflow is not on `main` yet).
- A real artifact attestation.
- Repository setting changes (the token got HTTP 403). See `docs/repo-settings.md`.
