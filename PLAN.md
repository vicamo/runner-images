# Runner image build and release plan

## Repository and commit workflow

- Maintain image support on `vicamo/runner-images:main`, based on the latest
  `actions/runner-images:main`. Refactor LXD container and VM builds while also
  attempting Linux and Windows Docker builds; resolve their failures later.
- Add Docker plugin/source wiring alongside LXD. Use
  `vicamo/archived/first-attempt` as a reference for Docker support, including
  Windows containers. Historical implementations need validation against current
  upstream; successful Docker builds are not a prerequisite for LXD progress.
- Develop on `lxd-wip`, with a pull request targeting `vicamo/main`.
- Keep this plan as the first development commit. Introduce the implementation
  in small, atomic commits after it.
- Amend requested corrections into their target commit and rebase subsequent
  commits. Push rewritten history only when requested.
- Refresh the upstream baseline before rebuilding the series.
- After adoption, integrate updates by merging `actions/runner-images:main`
  into `vicamo/main`, preserving upstream and published local history. Do not
  rebase or force-push published `main`. Development-series rewriting remains
  limited to the pre-release refactoring workflow described above.

## Build architecture

- One PR entry workflow selects an image matrix from the newly added CI label,
  then calls the reusable build workflow for each selected image. A label such
  as `CI ubuntu-2604` requests Docker, LXD container and, for x64, LXD VM builds.
  Arm64 images attempt Docker and LXD containers. Preserve `CI ubuntu-all`
  and `CI windows-all`. Windows CI labels select Windows Docker jobs on
  compatible Windows hosts, with platform-specific preparation actions. Do not
  create per-image skipped jobs for images outside the selected label's matrix.
- Use `pull_request` targeting `main`, so proposed workflow and local action
  changes are exercised. Trigger only on adding a matching CI label, not on
  `synchronize`. Remove and re-add the label to build after new commits.
- Cancel superseded PR builds for the same PR and image type, including when
  individual and all-image labels overlap; keep different images independent.
  This cancellation policy does not apply to release runs. Do not configure
  required image checks at this stage.
- Share preparation, build, packaging and testing through local composite
  actions, backed by scripts for substantial logic.
- Workflows own runners, matrices, job permissions and release orchestration.
  Local actions run after checkout and inherit their job's permissions.
- Each format has its own job and report names; a failure does not cancel the
  other formats. Build, package and smoke-test on the same runner to avoid
  transferring large intermediate images.
- Keep Docker failures visible and collect diagnostics without canceling or
  blocking independent LXD jobs/releases. Defer Docker compatibility fixes to
  later commits; never publish a failed or untested build as a successful image.
- PR validation includes packaging and upstream image tests, without publication.
- LXD VM jobs require KVM. Detect capabilities before constructing the matrix
  and skip VM jobs when KVM is unavailable, with an explicit summary rather than
  failing otherwise supported builds. Release orchestration must tolerate those
  skips, publish only successfully built artifacts, and never claim a skipped
  VM was tested or published. A VM-only request without KVM produces no image
  release or moving-tag promotion and reports the unsupported capability.
- Do not trigger image builds on branch pushes to `main`. Use label-triggered
  PR validation and explicit releases through manual dispatch.

## Packer definitions and output formats

- Share Ubuntu provisioning across sources where their behavior is compatible.
- Keep backend sources separate and select a single source per job using
  Packer's `-only` option. Initialize the appropriate LXD or Docker plugin.
- Filter source-specific provisioners and retain runtime detection where
  shared scripts need it.
- Initially attempt direct Packer Docker builds using the archived branch as
  a reference. Audit Linux root execution, uploads, systemd and boot assumptions,
  and Windows restart, servicing and Sysprep assumptions as failures arise.
  Windows Docker jobs require compatible Windows hosts and container base images.
- LXD artifacts stored in OCI must preserve what LXD needs to import them:
  metadata and rootfs for containers, metadata and disk for virtual machines.
  Extracting a VM rootfs into a runnable Docker image does not preserve a VM.
- Use ORAS to publish and retrieve LXD OCI artifacts with independent payload
  blobs. Preserve the exported metadata tarball, including any templates, and
  the complete qcow2 disk for VMs. Split large payloads into ordered chunks
  below registry limits and record their sizes, order and checksums.
- Define a versioned artifact contract: a custom artifact media type identifies
  each package format; payload media types identify metadata archives, disk
  chunks and compression. A JSON config records schema version, disk format,
  compression, ordered chunk references and the reconstructed disk checksum.
  Reuse OCI descriptor digests and sizes rather than unnecessarily duplicating
  them. Helpers reject unsupported schemas and verify blobs and the final disk.
- Chunk size, compression and sparse-file handling remain to be decided during
  packaging implementation.
- The download helper streams chunks directly into the final disk file rather
  than storing chunks and an assembled copy. LXD import may still require
  separate storage for its managed disk.
- Rewrite the original VM-to-rootfs helper later in the VM packaging commit.
  Do not assume a single partition or discard boot partitions. Defer additional
  LXD import/boot and standalone QEMU tests; use upstream image tests for now.
- Docker outputs are native runnable container images with explicit user,
  environment, working directory and command configuration.
- Validate layer size limits, including individual oversized files, available
  disk space, filesystem metadata preservation and import/runtime behavior.

## Independent release identities

Compose `image_type` from separately modeled OS version, architecture and
format. Always place `-amd64` or `-arm64` immediately after the OS identifier
for architecture-specific images. Use `-lxd` for LXD containers, `-vm` for VM
disks usable with LXD and standalone QEMU, and `-docker` for runnable Docker
images. VM builds can use LXD without encoding that builder in the artifact
name. Initial types for Ubuntu 26.04:

```text
ubuntu2604-amd64-lxd
ubuntu2604-amd64-vm
ubuntu2604-amd64-docker
ubuntu2604-arm64-lxd
ubuntu2604-arm64-docker
```

Use the same OS/architecture/backend convention for Windows Docker types, such
as `windows2022-amd64-docker`. Attempt builds first and enable publication only
for types that pass their applicable provisioning tests.

Apply the same naming to Ubuntu 22.04 and 24.04. Arm64 LXD VM images are outside
the initial set; if supported later, use `ubuntu2604-arm64-vm`.

Reserve architecture-free names such as `ubuntu2604-docker`, `ubuntu2604-lxd`
and `ubuntu2604-vm` for optional multi-architecture OCI indexes. Build and publish each architecture
on its own runner, then assemble the index from published digests without
downloading image layers into the index job. Independent architecture releases
remain available; publish a shared index only for compatible released variants.

Release each image type independently. Proposed naming:

```text
Release Git tag:     <image_type>/<date>.<minor>
Image version:       <date>.<minor>.<pico>
OCI version tag:     <image_type>-<date>.<minor>.<pico>
OCI moving tag:      <image_type>-latest
```

- `date` is the UTC date the release series starts, fixed by the release tag.
- `minor` is `git rev-list --count 92cd4626..<tagged-commit>`, counting all
  reachable commits after the anchor, including the tagged commit. It is not
  a timestamp ordering or a workflow run number. All image types tagged at
  the same source commit share the minor.
- `pico` identifies an explicitly requested image revision, independent of
  `github.run_attempt` and workflow run IDs. Start at `.1`; retries of failed
  builds and recovery through replacement runs keep the allocated pico.
  Allocate `.2` and later revisions only for explicit rebuild requests.
  Every pico must use the exact source SHA recorded for `.1`, never a newer
  branch HEAD. The release Git tag omits pico; `.1` identifies the first image
  version/OCI tag.
  Source corrections always land on `main` and require a new minor release tag.
- Bind each release tag permanently to its source SHA using structured metadata
  in a draft/published GitHub Release. Record allocated picos, build status,
  published versions/digests and workflow run IDs for provenance. Replacement
  runs may recover the same revision; do not enforce exclusive run ownership.
- Serialize revision allocation and builds per release tag. Ordinary retries
  select the existing revision; explicit rebuild requests allocate the next
  pico from the persistent record. Failed builds retain their allocation for
  retry, and independent runs must not build the same revision concurrently.
- Never overwrite a published full-version OCI tag. Persist the published
  version and digest so retries after publication reuse the existing image.
  Metadata-only retries never allocate another pico or rebuild the image.
- Do not create or build from `releases/*` maintenance branches. All release
  fixes go through `main`; release dispatches accept only a `main` ref or an
  explicitly selected commit on its history. Tagged builds and pico retries
  check out the recorded release SHA and reject source mismatches. Never move
  an existing release tag.
- Release only commits on `main`; once the repository is in use, do not rewrite
  its published history. Fetch full history, verify the anchor and tagged
  commit are ancestors of `main`, and validate the minor encoded in each tag.
  Ancestry validation is sufficient; do not impose a first-parent restriction.
- Create a release tag only for a new release. For retries and explicit pico
  rebuilds, reuse the existing tag after validating its recorded source SHA.
  Never replace an existing tag or accept a conflicting release identity.

## Release orchestration and permissions

- Rename/adapt `create_github_release.yml` into a release orchestration
  workflow triggered only by `workflow_dispatch` on `main`, replacing the
  external `repository_dispatch` payload with explicit inputs and generated
  build results. Tag pushes do not trigger release builds.
- Dispatch selects an implemented image type and a new-release, retry or
  explicit-rebuild operation. New releases resolve the selected source on
  `main`, calculate the date/minor, create the tag and allocate `.1`. Retries
  identify an existing release/revision and reuse its source and pico. Explicit
  rebuilds identify an existing release and allocate its next pico at the same
  source SHA. Reject dispatches whose workflow ref is not `main`.
- The preparation job validates tags and persistent release records, then
  continues through build, publish and release jobs in the same workflow run.
- Check out the tagged source and call the same local build actions as PR CI.
- Build, package, test and publish the selected image type to GHCR, then
  create its GitHub Release with reports, checksums, image digest and source
  commit details.
- Build/test jobs need `contents: read`; GHCR publication additionally needs
  `packages: write`. Tag creation and release metadata jobs need `contents: write`.
- Create the release tracking draft during preparation; finalize and publish it only
  after all required builds/tests and image publication succeed. Handle partial
  publication and retries explicitly.
- Serialize moving-tag promotion per image type and compare candidate and
  current versions before updating `latest`. An older release completing later
  must not replace a newer release. Promote only successful releases.
- Keep full version tags distinct across formats and architectures. Published
  digests record the exact artifacts even if a moving tag later changes.
- Create release tags using `GITHUB_TOKEN` and continue in the same dispatch
  run. No tag-push release trigger or second dispatch is needed.
- GitHub release flavors share one repository release history and a single
  repository-wide latest-release endpoint; flavor-specific discovery uses
  image type prefixes and OCI moving tags.

## Commit refactoring and validation

- Reuse upstream's Pester software and system tests during provisioning rather
  than duplicating that suite. Stick to those image acceptance tests initially.
  Defer new artifact launch/import tests, standalone QEMU boot tests and Docker
  runtime tests. Local workflow and packaging-helper validation still applies.
- Later add an
  end-to-end runner test for trusted CI or release builds: launch a disposable
  instance from the finished artifact, install and register an ephemeral GitHub
  Actions runner with a unique label, and run a smoke-test job covering checkout,
  a JavaScript action and a small build. Collect logs and destroy the instance.
- Obtain registration credentials through a narrowly scoped GitHub App with
  repository administration permission; ordinary workflow `GITHUB_TOKEN` cannot
  perform registration. Inject only temporary registration configuration into
  the test instance, never into the published image. Keep upstream image tests
  available for fork PRs without registration credentials.
- The hosted job keeps the disposable runner alive while the separate smoke-test
  job executes. Do not make the smoke-test job depend on completion of its hosting
  job. Bound wait times and clean up instances and registrations on failure.
- Refactor the original workflow introduction for PR CI and shared actions.
- Fold the LXD pool-directory correction into its originating commit.
- Preserve separate changes for format matrices, reports, release control,
  build outputs, exports, OCI packaging and publication where appropriate.
- Revisit the existing VM-to-rootfs conversion before treating it as VM
  packaging, and prevent VM/container jobs from publishing the same OCI tag.
- Validate workflow/action syntax and helper behavior locally, then use this
  PR for hosted integration tests as implementation commits are added.
- The initial plan commit documents the design; it does not itself create
  or validate runnable Docker/LXD images.
