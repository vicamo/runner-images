# Upstream release / pre-release process

Analysis of how `actions/runner-images` (upstream `main`) ships an image, so we
can decide which parts to reuse. All references are to files at the analyzed
`upstream/main` tip. This repo's own build path (the reusable
`build-runner-images.yml` + local composite actions) is NOT described here; this
document is only the *upstream* release machinery.

## The two halves

The release process is split across two systems:

1. **Azure DevOps (ADO)** — owns orchestration and the actual deployment. The
   build pipeline bakes the image (Azure Managed Image / VHD), a release
   pipeline rolls it out to the hosted fleet, and ADO is what decides *when* a
   deployment starts and finishes. None of this lives in the git repo except
   the helper scripts under `images.CI/linux-and-win/`.
2. **GitHub Actions (this repo)** — a set of thin, *reactive* workflows. They do
   no orchestration of their own; each one only reacts to an external
   `repository_dispatch` event that ADO sends, or to a PR label. They exist so
   that the GitHub-visible artifacts (the release entry, the docs PR, the SBOM
   asset) stay in sync with the ADO deployment.

The GitHub side is therefore a **state-mirror**, not a state-owner. ADO owns the
truth; the dispatches move the GitHub mirror between states.

## Trigger inventory

GitHub workflows and what starts them:

| Workflow                   | Trigger                                   | Role |
|----------------------------|-------------------------------------------|------|
| `ubuntu*/windows*.yml`     | `pull_request_target` (label on image PR) | PR-time CI: fan out to the build trigger |
| `trigger-ubuntu-win-build` | `workflow_call` (from the above)          | Dispatch a build into the CI repo, wait, report |
| `create_pull_request`      | `repository_dispatch: create-pr`          | Open the `<release>-docs` PR into the PR base |
| `merge_pull_request`       | `repository_dispatch: merge-pr`           | Resolve conflicts, approve, squash-merge the docs PR |
| `create_github_release`    | `repository_dispatch: create-github-release` | Create the GitHub release/pre-release entry |
| `update_github_release`    | `repository_dispatch: update-github-release` | Flip `prerelease` true/false on an existing release |
| `create_sbom_report`       | `repository_dispatch: generate-sbom`      | Attach an SBOM asset to a release |

Everything named `repository_dispatch` is sent by ADO; the dispatches are the
seams where we could hook in.

## Two distinct flows

There are two separate things people call "the process". Keep them apart.

### A. PR-time CI (contribution validation)

Runs when a maintainer labels an image PR. Does NOT release anything.

```
Image PR opened
      |
      | maintainer adds label  (e.g. "CI ubuntu-2404" / "CI ubuntu-all")
      v
ubuntu2404.yml (pull_request_target: labeled)
      |  if label matches
      v
trigger-ubuntu-win-build.yml  (reusable)
      |
      +--> trigger-workflow : DispatchWorkflow("trigger-<image>-build") into vars.CI_REPO
      |        then poll GetWorkflowRuns until a run's display_title matches a per-PR GUID
      |
      +--> wait-completion : WaitWorkflowCompletion.ps1 (blocks on the CI repo run)
      |        writes a summary table (run link + result)
      |
      +--> cancel-workflow : if cancelled() -> CancelWorkflowRun(ci run)
```

Notes that matter for reuse:
- The real build runs in a *separate* CI repo (`vars.CI_REPO`), reached with
  `secrets.CI_PR_TOKEN`. The public repo never builds the image itself here.
- Correlation is by a freshly generated GUID appended to the PR title
  (`pr_title = "<title> - <guid>"`), then matched against each run's
  `display_title`. Brittle-but-simple; no run id is returned by the dispatch.
- Polling: 10 attempts x 30s to find the run before giving up.

### B. Release / pre-release (deployment mirror)

Driven entirely by ADO via `repository_dispatch`. This is the state machine
the README documents (section "Image Releases"):

> A pre-release is created when the deployment of an image has started. As soon
> as the deployment is finished, the pre-release is converted to a release.

```
                         (ADO build pipeline produces a new image version)
                                          |
                                          | ADO: deployment STARTS
                                          v
      repository_dispatch: create-github-release   (Prerelease = true)
                                          |
                         create_github_release.yml
                         ncipollo/release-action, allowUpdates:true
                         tag = <ReleaseBranchName>, prerelease = true
                                          v
                               +---------------------+
                               |   PRE-RELEASE       |   <- "awaiting-deployment"
                               |  (prerelease=true)  |
                               +---------------------+
                                          |
                     (optional, any time while the release exists)
          repository_dispatch: generate-sbom --> create_sbom_report.yml
                     attaches sbom.<agentSpec>.json.zip asset
                                          |
                                          | ADO: deployment FINISHES
                      +-------------------+--------------------+
                      |                                        |
                      v                                        v
   repository_dispatch: update-github-release    repository_dispatch: create-pr
            update_github_release.yml                 create_pull_request.yml
            flip prerelease -> false                  branch <release>-docs off <release>
                      |                               open PR into PullRequestBase
                      v                               request runner-images-team review
            +---------------------+                              |
            |   RELEASE (GA)      |                              v
            |  (prerelease=false) |             repository_dispatch: merge-pr
            +---------------------+                  merge_pull_request.yml
                                                     merge main into <release>-docs
                                                     (strategy-option=ours),
                                                     bot APPROVE, squash-merge
                                                              |
                                                              v
                                                   docs on `main` now reflect
                                                   the deployed image
```

#### State semantics

- **PRE-RELEASE**: GitHub release entry exists with `prerelease=true`. Created
  the moment ADO begins rolling the image to the fleet. Subscribers are
  notified. Tracked in the UI by the `awaiting-deployment` label.
- **RELEASE (GA)**: same entry, `prerelease=false`. Set once the rollout
  completes. The only change is the boolean flip via `update-github-release`.
- The GitHub release is **created once and mutated in place** (`allowUpdates`,
  `updateRelease`), not recreated. `ReleaseBranchName` doubles as the tag and is
  the join key across every dispatch.

#### The two doc commits (release branch vs main) — when they "merge"

A single image version produces **two separate commits of the same README
delta**, and they are never literally merged into one. They are the same change
copied across two refs at two different times:

1. **On the release branch, at deploy start.** When ADO cuts
   `releases/<image>/<date>`, the bot commits the regenerated readme there, e.g.
   for ubuntu22 `20261111.360`:
   `d797dfd4e "Updating readme file for ubuntu22 version 20261111.360.2"`
   (author/committer *Hosted Runners Images Bot*, 2026-11-12). This commit is
   also what the `ubuntu22/20261111.360` tag points at. The release branch is a
   frozen snapshot; this commit stays on it forever and is **never merged into
   main by ref** (`d797dfd4e` is not an ancestor of `main`).

2. **On main, at deploy finish.** The `<...>-docs` PR (opened by
   `create_pull_request.yml`, squash-merged by `merge_pull_request.yml`) lands a
   **fresh commit** on main carrying the identical delta:
   `b727fd64e "Updating readme file for ubuntu22 version 20261111.360.2 (#15311)"`
   (author `github-actions[bot]`, committer `GitHub`, 2026-11-13). It has a
   single parent (squash merge, not a merge commit) and the `(#15311)` suffix is
   the PR number.

Proof they are the same change: both commits have the identical
`git patch-id` (`9e109245…` for the `Ubuntu2204-Readme.md` delta). Different
SHAs only because one is the original bot commit on the release branch and the
other is the squashed PR commit on main.

So the user's example — `b727fd64e` (in main) and `03b11f229` (in a release
branch) — are not two halves of one change awaiting a merge. They are the
**main-side and release-side copies of different cycles**: `b727fd64e` is the
*landed* main copy of ubuntu22 `20261111.360`, while `03b11f229` is the
*release-branch* commit of the **later** `20261116.365` cycle whose docs have
**not yet landed in main** (that cycle's deployment was still in flight at
analysis time; no `…20261116.365… (#NNNN)` squash exists on main).

Timing: release-branch commit at deploy start (2026-11-12 09:33Z) →
squash-merge into main at deploy finish (2026-11-13 16:32Z), ~1.3 days later,
matching the README rule that `main` docs update only when deployment finishes.

```
deploy START                                deploy FINISH
     |                                             |
     v                                             v
releases/ubuntu22/20261111                      main
  d797dfd4e  ---- same patch-id (9e109245) ---->  b727fd64e
  "...360.2"     (NOT merged by ref;              "...360.2 (#15311)"
  tag 20261111.360  copied via -docs PR)          squash, 1 parent
     ^                                             ^
 bot commit                                    squashed -docs PR

(the in-flight cycle, 20261116.365:  release has 03b11f229, main has nothing yet)
```

#### The docs branch dance (why there are two branches)

`create_pull_request.yml` does not PR the release branch directly. It:
1. checks out `<ReleaseBranchName>`,
2. creates a sibling `<ReleaseBranchName>-docs` branch,
3. force-pushes it, and opens the PR from `-docs` into `PullRequestBase`.

`merge_pull_request.yml` then merges `main` into `<...>-docs` with
`--strategy-option=ours` (keep the release's doc content, absorb main's history
so the squash-merge is conflict-free), waits 30s, bot-approves with
`PRAPPROVAL_SECRET`, and squash-merges with `GITHUB_TOKEN`. The `-docs` branch
exists only to carry the README/software-version changes back to `main`
*after* deployment, matching the README note that "documentation in the `main`
branch is only updated when deployment is finished."

## ADO-side helpers in this repo

`images.CI/linux-and-win/`:
- `build-image.ps1` — Packer wrapper that bakes the Azure Managed Image
  (`ManagedImageName`, resource groups, SIG, etc.). This is the "build" that
  precedes the whole diagram above.
- `create-release.ps1` — POSTs to the ADO *release* pipeline
  (`vsrm.dev.azure.com/.../releases`) with `ImageBuildId` / `ImageType` /
  `ManagedImageName`. This is the ADO deployment that later emits the
  `create-github-release` etc. dispatches. It is the real "deploy" trigger.
- `cleanup.ps1`, `measure-provisioners-duration.ps1`, `shebang-linter.ps1` —
  supporting.

So the chain's true head is: ADO build pipeline -> `create-release.ps1` ->
ADO release pipeline -> (dispatches) -> the GitHub state machine above.

## External dependencies (what a fork must supply)

- `vars.CI_REPO` — the private repo that actually runs image builds for PR CI.
- `secrets.CI_PR_TOKEN` — token with access to dispatch/read runs in `CI_REPO`.
- `secrets.PRAPPROVAL_SECRET` — identity allowed to request reviewers and to
  approve the docs PR (must differ from the token that merges).
- The ADO organization/project/release-definition targeted by
  `create-release.ps1`.
- The whole release *ownership* (deciding start/finish, the actual fleet
  rollout) lives in ADO and is NOT in this repo.

## Reuse assessment (for our purposes)

- **Reusable as-is**: the pre-release -> release *pattern* — create one release
  entry with `prerelease=true` at deploy start, flip to `false` at deploy
  finish. Our OCI-image build already produces versioned artifacts; we can mirror
  the same two-state release the same way.
- **Needs replacement**: the ADO half. We have no ADO release pipeline, so
  `create-release.ps1` and the `repository_dispatch` senders don't apply. We
  would drive the state transitions from our own GitHub workflow (the thing
  that finishes a build) instead of from an external dispatch.
- **Reconsider**: the `-docs` branch + two-token bot-approve/squash-merge dance
  is heavy and exists to satisfy upstream's "docs only land after deploy" rule
  and branch protections. For our flow a plain commit/PR from the build job is
  almost certainly enough; adopt the two-state release idea without the docs
  choreography.
- **Decoupling seam**: everything hinges on `repository_dispatch` types
  (`create-github-release`, `update-github-release`, `create-pr`, `merge-pr`,
  `generate-sbom`). If we ever want ADO-style separation, those are the exact
  events to emit; otherwise we collapse them into direct steps.
```

