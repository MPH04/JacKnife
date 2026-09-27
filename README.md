# JacKnife

Standalone hardened fuzzing platform. It builds a sanitizer-instrumented
libFuzzer harness for its own packet parser, classifies crashes with its own
evidence ladder, and writes a JSON artifact another tool can fetch.

JacKnife is not part of JacBox.

Security through defensive attack strength: every crash is replayed, minimized
only when the sanitizer class stays the same, and labeled `Confirmed` only
after a consumer has checked the GitHub Actions run. The producer artifact
never says `Confirmed`.

## Layout

- `target/` — `jkpacket` parser, harness, corpus
- `ladder/classify.jac` — the only classification logic
- `scripts/` — build, fuzz, validate, trigger
- `.github/workflows/fuzz.yml` — manual dispatch
- `docs/api-contract.md` — the interface
- `fallback/` — one real local run, for when GitHub is down

## Local fuzz

```bash
bash scripts/install_toolchain.sh
python3 -m pip install --user --break-system-packages --require-hashes -r requirements.txt
export PATH="$HOME/.local/bin:$PATH"
bash scripts/build_fuzzer.sh
bash scripts/reproduce_crash.sh target/corpus/seed_heap.bin
JACKNIFE_DURATION=20 JACKNIFE_SEED=1 JACKNIFE_CRASH_DIR=runs/crashes bash scripts/run_fuzzer.sh
python3 scripts/collect_state.py --crash-dir runs/crashes --out-dir dist/artifact \
    --source local --run-id local --duration 20 --seed 1
python3 scripts/validate_artifact.py --dir dist/artifact --check-targets
```

## Fetch a GitHub run

The workflow has to be on `main` before GitHub will dispatch it.

```bash
export JACKNIFE_GITHUB_TOKEN="..."
python3 scripts/trigger_and_poll.py --repo MPH04/JacKnife \
    --run-id "$(uuidgen)" --duration 90 --seed 1 --out-zip run.zip
```

Do not pass the token as an argument. Details, the JSON schema, and the
meaning of `Confirmed` are in `docs/api-contract.md`.

## Tests

```bash
export PATH="$HOME/.local/bin:$PATH"
python3 -m unittest discover -s tests -v
```

## Unfinished

- GitHub Actions has not been dispatched from this environment. The workflow
  file is on a branch until it is merged.
- Artifact attestation is wired and not yet verified. `scripts/verify_attestation.py` fails closed.
- Repository settings in `docs/repo-settings.md` need an owner token. The API returned 403 here.
