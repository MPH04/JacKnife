# Security policy

JacKnife fuzzes its own packet parser and publishes the evidence. It does not
accept third-party targets, and it is not part of JacBox.

## In scope

- The `jkpacket` parser in this repository
- The fuzz workflow, artifact validator, evidence ladder, and CLI in this repository
- Hardening findings about JacKnife's own GitHub Actions permissions and artifact handling

## Out of scope

- JacBox, JacHammer, or any other repository
- Crashing, scanning, or fuzzing code you do not own
- Using crash inputs from this repo against any other program
- Social engineering, secret theft, or anything outside this repository

The seeded bugs in `target/jkpacket.c` are intentional and local. A sanitizer
report here is a test fixture, not a vulnerability in anyone else's software.

## Reporting

Open a GitHub Security Advisory on `MPH04/JacKnife`, or email the maintainer
listed on the GitHub profile if advisories are unavailable. Please include the
workflow run URL and the `finding_id` if you are reporting a bad artifact.
Do not send exploit payloads aimed at other projects.

## What a finding label means

`Confirmed` is defined in `docs/api-contract.md`. It is not a CVE, a CVSS
score, or a claim that the bug is exploitable.
