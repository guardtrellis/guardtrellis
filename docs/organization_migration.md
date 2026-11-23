# SDK organization migration

This runbook covers the existing public SDK repository's move from
`sahilmathur254/guardtrellis` to `guardtrellis/guardtrellis`. A prepared patch does not
establish that the transfer, publisher changes or app installations have happened.
The maintainer retains control. Package name `guardtrellis`, author/project-owner records,
SDK behavior, dependency requirements and the current version remain unchanged.

Companion/demo transfers, their private-repository feature requirements, personal Projects
and Cursor's repository contents/marketplace configuration are separate. The separately
approved organization ChatGPT Codex Connector grant covers **All repositories**, including
Cursor and future private/transferred repositories. Record that app scope in the baseline;
it does not itself transfer a repository or change its contents. The roadmap remains the
[existing personal Project](https://github.com/users/sahilmathur254/projects/3).

## Prepare before the ownership change

1. Preserve unpublished work in its original checkout. Prepare this migration on an
   isolated branch/checkout; completing unrelated SDK work is not a transfer prerequisite.
2. Review the two organization-only publication guards in `release.yml`, their regression
   tests, project URLs, generated README release block and current canonical links.
   Preserve frozen evaluations, accepted contracts, recorded commits/runs and historical
   release evidence. Regenerate with `python scripts/release_artifacts.py sync`, then run
   the source checks and focused release tests. This change does not require a version bump
   or lockfile rewrite.
3. Review the patch and require the existing native CI matrix, including Windows, package
   checks and actual Python/Actions CodeQL analyses on its submitted revision. Local checks
   do not establish hosted CI success. The organization-only guards intentionally prevent
   publishing from the personal namespace if the patch merges before the transfer; do not
   add a second allowed owner to work around the cutover.
4. Confirm administrator access, destination-name availability and a release-free cutover
   window. Do not create a placeholder `guardtrellis/guardtrellis` repository. Finish any
   active publishing/rehearsal transaction before transferring.
5. Inspect the personal Codex/ChatGPT app identities and permissions, then verify the
   corresponding organization installation and its separately approved **All repositories**
   scope. Verify access to the SDK after transfer; a personal installation is not proof
   of organization access. Preserve that approved app scope while keeping Cursor's source
   and marketplace configuration outside this SDK patch.
6. Configure and inspect replacement publishers on both existing index projects using
   the exact [release-guide values](releasing.md#existing-project-replace-the-github-workflow-identity).
   Keep project-owner recovery access. Publisher registration, app access and ownership
   changes need their explicit authorization; local code changes do not perform them.

## Record the cutover baseline

Immediately before transfer, retain a dated, access-controlled settings snapshot outside
the public source tree. Record metadata and settings without exposing secret values:

- Repository ID, owner, public visibility, default branch and exact `main` commit;
  collaborators/team roles and organization defaults.
- The complete `Protect main` ruleset: conditions, bypass actors, branch-integrity and PR
  requirements, exact required check names/provider IDs and strict status-check behavior.
- Actions enablement, allowed actions, default token permissions, fork-approval settings,
  hosted-runner availability and artifact retention; the existing CI and advanced CodeQL
  workflows. Preserve Python/Actions scanning and the current default-setup mode.
- Both `testpypi` and `pypi` environments: reviewer identities, `main` branch policies,
  administrator bypass disabled and the existing self-review setting. A sole reviewer
  who dispatches releases must be able to approve them, or another reviewer is needed.
- Security-feature states, including Dependabot security updates, secret scanning and push
  protection. Preserve reviewed disabled states too; migration is not a new policy change.
- Secret/variable names and scopes, webhook/deploy-key metadata, and app repository
  selections/permissions. Do not place secret values, tokens or private baseline exports
  in this repository or a PR.
- Both indexes' old/new publisher definitions and continuing project-owner access.

GitHub's [transfer documentation](https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository)
describes retained repository data and destination organization defaults. Verify the actual
result against the snapshot; the transfer operation alone is not evidence of preservation.

## Transfer and verify

After the migration patch and cutover are approved, transfer the existing repository
without changing its name or public visibility. The default sequence is to review the
migration PR before transfer, then merge it at the new address so its resulting `main`
push produces fresh native CI and CodeQL evidence. Confirm the repository ID, history
and default branch are retained, then compare every baseline category above. Resolve
missing app/repository selections and verify Codex/ChatGPT access at the new address.

Update local clones' remotes after confirming the destination. Keep the old repository
namespace unused so GitHub redirects remain intact. Do not recreate it as a replacement
repository. Keep the separate personal Project URL until its own migration is approved.

Require green native CI, especially Windows, and processed Python/Actions CodeQL analyses
on the resulting `main` revision. If the patch was merged before transfer, explicitly
rerun the existing exact-main checks and CodeQL after transfer and inspect those new
executions. The native CI workflow has push/PR triggers, so release validation alone
cannot supply that matrix evidence. Then run the publication-free candidate validation:

```sh
gh workflow run release.yml --repo guardtrellis/guardtrellis --ref main -f target=validate
```

Inspect candidate metadata, generated links and fresh wheel/sdist installation checks.
`validate` skips publishing-specific prerequisites and upload jobs: it proves neither
OIDC authentication nor the retained environment protections. Compare those settings
directly and keep the [release approval gates](releasing.md#rehearse-then-promote).

## Next planned release and external follow-up

For the next separately approved release, choose a version unused on both indexes and
start a fresh TestPyPI rehearsal from the final migrated `main` commit. Record the original
`candidate` producer artifact ID and rehearsal run ID, then promote those exact bytes to
PyPI without advancing `main` or rebuilding. Do not carry a pre-transfer rehearsal into
this release. Each index's successful OIDC upload establishes its own publishing access;
TestPyPI success does not prove the independent PyPI registration.

Deliberately remove obsolete publisher entries only after inspecting the replacement
registrations and recovery access. No upload is required solely to remove an old entry.
New canonical package links appear with a future upload; existing package metadata,
artifacts and provenance retain their historical identities.

After the transfer, ask the XERJ maintainer to update the existing
[GuardTrellis corpus entry](https://hub.xerj.org/corpus/sahilmathur254--guardtrellis) to the
new source URL. Retain Sahil Mathur's personal attribution, licence/consent history and
original selected contribution. Repository-link updates and corpus re-pinning are separate:
the whole-repository snapshot at `d722ec2c04` does not advance when GitHub changes. Request
a newer published-release pin only as a separate content update, then verify the resulting
source link and pin. Do not add private repositories as part of this SDK follow-up.

## Failure and recovery

If a preservation, access or CI check fails, hold publication and fix the specific gap
without weakening protections. Before transfer, reverting this migration-only patch can
restore the personal-namespace release gate. After transfer, prefer a reviewed forward
fix; an ownership reversal requires its own approval and destination-availability check.
Keep the baseline for comparison. Published packages and historical provenance are not
rewritten as a rollback; use the [release recovery process](releasing.md#failure-and-recovery).
