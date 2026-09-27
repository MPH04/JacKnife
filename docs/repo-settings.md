# Repository settings

The GitHub token available to this authoring environment received HTTP 403
(`Resource not accessible by integration`) for every admin call below. Nothing
in this list is enabled by the code in the pull request. An owner has to run
the commands, or click the same settings in the UI.

Checked on 2026-09-27 against `MPH04/JacKnife`.

## Description

```bash
gh api -X PATCH repos/MPH04/JacKnife \
  -f description='Standalone hardened fuzzing platform — produces verified findings for external consumption. Not part of JacBox.'
```

UI: Repository **Settings → General → Description**.

## Default workflow token is read-only

```bash
gh api -X PUT repos/MPH04/JacKnife/actions/permissions/workflow \
  -f default_workflow_permissions='read' \
  -F can_approve_pull_request_reviews=false
```

UI: **Settings → Actions → General → Workflow permissions → Read repository contents**.

The fuzz workflow already sets `permissions: {}` at the top and grants each
job only what it uses. The repo default is still the backstop for any future
workflow that forgets.

## Approval for first-time contributors

UI: **Settings → Actions → General → Fork pull request workflows → Require approval for first-time contributors**.

Not verified: the REST field that matches this checkbox. Do not guess it.
The workflow file itself has no `pull_request` trigger.

## Secret scanning and push protection

```bash
gh api -X PATCH repos/MPH04/JacKnife --input - <<'JSON'
{
  "security_and_analysis": {
    "secret_scanning": {"status": "enabled"},
    "secret_scanning_push_protection": {"status": "enabled"}
  }
}
JSON
```

UI: **Settings → Code security → Secret scanning**, and **Push protection**.

## Protect main

```bash
gh api -X PUT repos/MPH04/JacKnife/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": null,
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null
}
JSON
```

UI: **Settings → Branches → Branch protection rule** for `main`: require a
pull request, at least one review, and include administrators.

Not verified: any of these calls succeeding. Required verification: rerun
them with a token that has repo administration, then `gh api repos/MPH04/JacKnife/branches/main/protection`.
