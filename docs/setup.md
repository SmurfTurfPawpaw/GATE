# Laptop and cloud setup

GATE uses the laptop as its primary execution environment. On Windows, the control plane runs in WSL2 while hardware-facing and Windows-target tools stay native. Docker is optional and organizes conflicting command-line stacks; the base workflow does not depend on it.

The setup has four layers:

1. Windows provides Codex access to the laptop, native browsers, certificate stores, packet capture, USB devices, and Windows applications.
2. WSL2 provides the Linux control plane, Git worktrees, Node tooling, and agent CLIs.
3. GATE keeps private runtime state outside the tracked repository.
4. Planned pinned OCI profiles will provide repeatable dependency-heavy tool environments. The repository does not ship Docker Compose tool profiles in v0.1.

## Supported baseline

The recommended Windows baseline is:

- Windows 11 with current WSL2 and Ubuntu 24.04;
- Git, GitHub CLI, and Codex CLI inside WSL;
- Node 24.x with npm 11.x; the minimum for the GATE package is Node 22.20;
- Bubblewrap and `prlimit` for the fixed offline-analysis lane and managed-runtime smoke checks;
- Python 3.12 managed by `uv` for isolated Python tools;
- Go installed only when a pinned Go upstream requires it;
- Docker Desktop with WSL integration when OCI tool profiles are needed;
- Wireshark with Npcap, Burp Suite or OWASP ZAP, and hardware-specific utilities installed on Windows when they need host integration.

Node 24 is the common compatible choice for GATE, the Skills CLI, AXI, Lavish, GNHF, and current REA work. Python 3.12 has broader security-tool compatibility than using the newest interpreter globally. GATE's target `isolated-python` lane gives each admitted Python tool its own environment; that general per-tool installer is not implemented in v0.1.

## 1. Prepare WSL2 on Windows

Open an elevated PowerShell and run:

```powershell
wsl --install -d Ubuntu-24.04
wsl --update
```

Restart Windows if requested. The ordinary lifecycle does not need an AI:

```powershell
wsl -d Ubuntu-24.04
wsl --shutdown
```

Inside Ubuntu, install the small native base:

```bash
sudo apt update
sudo apt install --yes bubblewrap build-essential ca-certificates curl git jq tmux unzip util-linux xz-utils
```

Install the tested official Node 24 binary under an administrator-owned path. The ownership and mode normalization matter: managed-upstream verification rejects root execution and any Node, npm file, or parent path that the normal operator can replace. These commands cover WSL on x86-64 and ARM64:

```bash
NODE_VERSION=v24.19.0
case "$(uname -m)" in
  x86_64) NODE_ARCH=x64 ;;
  aarch64|arm64) NODE_ARCH=arm64 ;;
  *) echo "Unsupported Node architecture: $(uname -m)" >&2; exit 1 ;;
esac
NODE_ARCHIVE="node-${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"
curl --fail --show-error --location --remote-name \
  "https://nodejs.org/dist/${NODE_VERSION}/${NODE_ARCHIVE}"
curl --fail --show-error --location --remote-name \
  "https://nodejs.org/dist/${NODE_VERSION}/SHASUMS256.txt"
grep " ${NODE_ARCHIVE}\$" SHASUMS256.txt | sha256sum --check -
sudo install -d -m 0755 /opt/nodejs
sudo tar -xJf "${NODE_ARCHIVE}" -C /opt/nodejs --no-same-owner
sudo chown -R root:root "/opt/nodejs/node-${NODE_VERSION}-linux-${NODE_ARCH}"
sudo chmod -R u=rwX,go=rX "/opt/nodejs/node-${NODE_VERSION}-linux-${NODE_ARCH}"
sudo ln -sfn "/opt/nodejs/node-${NODE_VERSION}-linux-${NODE_ARCH}" /opt/nodejs/current
for command_name in node npm npx corepack; do
  sudo ln -sfn "/opt/nodejs/current/bin/${command_name}" "/usr/local/bin/${command_name}"
done
rm "${NODE_ARCHIVE}" SHASUMS256.txt
hash -r
node --version
npm --version
node -e 'const fs=require("node:fs"); const p=fs.realpathSync(process.execPath); if (fs.statSync(p).uid===process.geteuid() || (()=>{try{fs.accessSync(p,fs.constants.W_OK);return true}catch{return false}})()) throw Error(`Node must be administrator-owned and read-only to this account: ${p}`)'
```

Do not substitute `nvm`, Volta, a user-owned extracted archive, or another user-writable Node tree for managed upstream operations. They remain fine for unrelated development in a separate shell, but GATE deliberately refuses to launch their npm implementation.

Install and authenticate the two required CLIs inside WSL. Codex may remain user-scoped because it is the interactive harness rather than a GATE-verified upstream runtime:

```bash
sudo apt install --yes gh
npm install --global --prefix "$HOME/.local" @openai/codex
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"
gh auth login
codex login
export GH_TOKEN="$(gh auth token)"
gh auth status
codex login status
```

If Codex was installed by another supported method, keep that installation and only run the verification commands. Export `GH_TOKEN` or `GITHUB_TOKEN` in each shell that performs a managed release install. The downloader uses a fresh GitHub CLI configuration directory, so it deliberately cannot consume credentials stored only by `gh auth login`; do not save the token in this repository.

## 2. Clone into the WSL filesystem

Git worktrees and file watching are faster and more predictable under the WSL filesystem than under `/mnt/c`. From the Ubuntu shell:

```bash
mkdir -p ~/src
cd ~/src
git clone https://github.com/SmurfTurfPawpaw/GATE.git
cd GATE
```

If the repository is already checked out on a Windows drive, `scripts/bootstrap.ps1` can launch it through WSL, but it will warn about the slower mount.

## 3. Bootstrap GATE

First run the read-only preflight:

```bash
./scripts/bootstrap.sh --check-only
```

Then prepare the locked JavaScript dependencies and private runtime:

```bash
./scripts/bootstrap.sh
```

The script runs `npm ci` with package lifecycle scripts disabled, creates the private runtime with `gate bootstrap`, and executes the smoke suite. It does not install system packages or broad security suites. Add `--install-core-tools` after the read-only preflight to install all seven reviewed core releases and make the final smoke require a nonempty installed and byte-verified core result.

By default, private state is stored under `~/.local/share/gate`. Set `GATE_HOME` before bootstrap if it belongs on another local disk:

```bash
export GATE_HOME="$HOME/.local/share/gate"
./scripts/bootstrap.sh
```

Keep this directory out of cloud-synced folders and Git. It contains events, registered project contracts, private learnings, engagement records, plans, offline-analysis manifests and input snapshots, evidence, managed upstream installations, content-addressed tool archives, managed tool staging and runtimes, installation receipts, and Treehouse's private state root. Project contracts can contain repository and deployment references even though general status and observer responses omit those details.

Keep upstream telemetry disabled in interactive shells as well as bootstrap runs. Add these values to the WSL shell profile used for GATE:

```bash
export DO_NOT_TRACK=1
export DISABLE_TELEMETRY=1
export GNHF_TELEMETRY=0
export NO_MISTAKES_TELEMETRY=0
export LAVISH_AXI_TELEMETRY=0
```

Restart the shell after editing the profile. A later explicit operator choice may enable a named provider, but GATE's default remains disabled.

GATE-managed npm and verified-release upstreams can be installed into this private root after the base smoke test passes:

```bash
./scripts/bootstrap.sh --install-upstreams
```

For npm upstreams, this verifies the committed dependency-lock digest recorded in `locks/upstreams.lock.json`, runs `npm ci` with lifecycle scripts disabled, and verifies the installed tree against a second offline reconstruction. It launches the bundled npm CLI through the exact running Node executable in a minimal environment and hashes the complete npm package tree before and after use. Full integrity checks later repeat that clean reconstruction from the lock and GATE's integrity-addressed npm cache before comparing the deterministic tree digest. Bootstrap also downloads the locked Treehouse and No Mistakes GitHub release artifacts with a fixed GitHub CLI, fresh configuration directory, and minimal token-and-proxy environment. It reads each bounded archive once, verifies and inspects those exact bytes, and asks fixed tar to emit only the locked executable to stdout instead of unpacking the archive tree. Export `GH_TOKEN` or `GITHUB_TOKEN` before a release download; the fresh configuration deliberately does not read credentials saved only by `gh auth login`. Upstream Git, tar, GitHub CLI, Node, npm, and every component of their path chains must be inaccessible for writes by the current process. Run these operations as a normal user with OS- or administrator-owned read-only tools; root, `nvm`/Volta-style user-owned Node installations, user-writable Homebrew trees, and writable `/usr/local` tools fail closed. Native Windows cannot establish this contract and must use WSL2. On WSL, prefer the distribution's protected `/usr/bin/git`, `/usr/bin/tar`, and `/usr/bin/gh` plus the administrator-owned Node installation above. The installer records version metadata from the reviewed lock and deliberately does not execute the freshly downloaded binary during installation. Receipts are evidence; the reviewed repository locks remain the trust anchor. The workspace CLI refuses Treehouse unless the installed executable still passes full integrity verification. Source, skill, native, GUI, and hardware tools follow their own reviewed lanes.

`gate upstream sync` always builds a fresh staged source clone with system and global Git configuration and templates isolated, verifies it against the locked commit, then atomically replaces the managed checkout. Full readiness compares the commit tree, index, and raw worktree bytes and rejects Git replacement mechanisms, hidden index flags, and every extra path, including ignored files and empty directories. Submodules are not initialized in v0.1 and therefore fail source readiness. Do not keep local work in a GATE-managed upstream checkout.

### Install the managed core tools

GATE has exact reviewed release locks for `subfinder`, `dnsx`, `httpx`, `katana`, `naabu`, `ffuf`, and `nuclei`. The `core` profile selects those seven tools. Review the effects for an individual tool, cache the exact release artifacts, install them into private state, and then rerun current-byte and live smoke verification:

```bash
./bin/gate.mjs tool plan subfinder --json
./bin/gate.mjs tool prefetch --profile core --json
./bin/gate.mjs tool install --profile core --json
./bin/gate.mjs tool verify --profile core --json
```

Each of `prefetch`, `install`, `verify`, and `remove` accepts either one tool ID, such as `tool install ffuf`, or exactly one `--profile ID`. A profile operation keeps every per-tool result and exits nonzero when any selected runtime remains unresolved; inspect `unresolved` rather than treating partial installation as success. `tool remove ID|--profile ID` atomically retires installed runtimes and receipts while retaining the content-addressed archive cache; the next reuse rechecks its exact size and SHA-256.

The lock binds each catalog-entry digest, version, full source commit, release and checksum evidence, artifact URL and size, archive and executable SHA-256, exact safe archive members, supported platform, and smoke arguments and limits. It contains artifacts for `linux-x64`, `linux-arm64`, `darwin-x64`, and `darwin-arm64`. `prefetch` verifies the downloaded archive bytes without executing the tool. Activation is currently Linux/WSL2 only: `install` and `verify` launch the exact executable with no shell inside a Bubblewrap-created zero-network namespace, then apply `prlimit` inside that namespace. macOS artifacts can be prefetched, but installation remains unresolved until GATE has an equivalent reviewed zero-egress smoke sandbox. Native Windows is not in this lock.

The installer uses a private content-addressed cache under `GATE_HOME/tool-cache/sha256`, stages an exact two-file runtime tree under `GATE_HOME/tool-runtimes/.staging`, smoke-tests it, and atomically publishes `bin/TOOL` plus `install.json` under `GATE_HOME/tool-runtimes/TOOL`. Archive traversal, links, devices, duplicate or case-colliding names, unreviewed extra members, size or digest drift, catalog drift, and executable drift fail closed. A receipt records evidence but cannot re-anchor changed bytes.

`tool list --profile core` is the cheap view: it performs no process execution or network access and treats an installation receipt as receipt-only evidence. Broader inventory can run an existing adapter's capability probe. `tool plan ID`, `tool verify`, and `doctor --full` rehash the installed executable and rerun its bounded zero-egress smoke. Normal `status` and `doctor` rehash current bytes but rely on the smoke evidence bound at install time. `gate status`, `gate doctor`, and the cockpit expose catalog, locked, installed, verified, executable, and unresolved counts. `executable` remains zero after all seven verify because workflow-phase admission is still unavailable; `unresolved` is a full-catalog readiness count, not a failed-install count.

Installing a runtime never grants target authority or execution admission. All seven core binaries remain invocation-blocked after live verification until a reviewed workflow-phase adapter binds each action and argument shape. `naabu` additionally needs a reviewed raw-network privilege adapter, and `nuclei` additionally needs its separately versioned template dependency admitted. A future active adapter must still require the exact engagement, tool allowlist, target/action check, and applicable confirmation. The other 119 catalog entries remain on their documented native, GUI, hardware, OCI, Python, Node, Java, source-build, or external installation lanes.

### Bootstrap the first No Mistakes config

No Mistakes reads repository controls from the fetched default branch, so a new `.no-mistakes.yaml` cannot govern the same pull request that introduces it. Run that first review with `--no-publish-intent`; independently run `npm ci --ignore-scripts`, `npm test`, and `npm run check`; manually review the complete diff and policy; and require normal CI. Treat the config as authoritative only after the pull request merges and the default branch is fetched again. Later config changes also take effect only after they are merged and trusted on the fetched default branch.

Use `axi run --no-publish-intent` for every run that may contain private task context. The trusted `pr.publish_intent: false` ceiling suppresses the generated Intent section, while the caller-side flag also withholds the full intent from the PR-drafting turns so they draft from the diff and commit messages. This environment sets the matching global operator default, but the explicit flag is the portable rule on another laptop or daemon.

From Windows PowerShell, the equivalent launcher is:

```powershell
.\scripts\bootstrap.ps1 -Distribution Ubuntu-24.04
.\scripts\bootstrap.ps1 -Distribution Ubuntu-24.04 -InstallCoreTools
.\scripts\smoke.ps1 -Distribution Ubuntu-24.04
```

## 4. Run and inspect

These commands use the current package interface:

```bash
npm run doctor
npm run validate
npm run dashboard
```

For ordinary repository work, start Codex with only the checkout writable:

```bash
codex -C "$HOME/src/GATE" --sandbox workspace-write --ask-for-approval on-request --search
```

Only add private state for a task that must run GATE control commands, and expose the narrowest suitable path. Adding the whole root is a deliberate trusted-session choice:

```bash
export GATE_HOME="${GATE_HOME:-$HOME/.local/share/gate}"
codex -C "$HOME/src/GATE" --add-dir "$GATE_HOME" \
  --sandbox workspace-write --ask-for-approval on-request --search
```

In v0.1, any process with write access to all of `GATE_HOME` can change project records, offline snapshots and manifests, engagement records, unsigned approval receipts, active-execution manifests, claims, stop records, run metadata, evidence, managed tool caches and runtimes, and installation receipts. It can therefore forge or erase local authority and execution provenance by rewriting the trust domain. Exclusive files and hashes provide workflow consistency against ordinary races and reuse; they do not protect state from its same-user owner. Managed-upstream bytes remain anchored to `locks/upstreams.lock.json`, and managed tool bytes remain anchored to `locks/tool-runtimes.lock.json` plus the bound catalog entry, rather than to writable installation receipts. Keep credential values outside this broad writable root in an OS secret store or narrowly permissioned file, and use symbolic references in GATE state.

Operations that need Npcap, a debugger, a certificate store, USB, or another host capability are operator-run native operations today. Record their versions, exact commands, and bounded evidence manually. Narrow native capability providers and their event bridges are a target design; v0.1 does not supply them.

The dashboard binds to `127.0.0.1:4173` by default. Open `http://127.0.0.1:4173` from Windows. WSL normally forwards the loopback port automatically. Do not bind the observer to a LAN address; it is a local view of private operational state.

Run the smoke suite after a runtime, dependency, or host change:

```bash
./scripts/smoke.sh
./scripts/smoke.sh --require-core-tools
# Equivalent for automation:
GATE_REQUIRE_CORE_TOOLS=1 ./scripts/smoke.sh
```

The base smoke validates schemas and pins, runs the tests, verifies required CLIs, exercises static status and catalog reads, and reports only the presence of optional executables such as Docker. It does not execute unmanaged optional tools or probe the Docker engine. `--require-core-tools` and `GATE_REQUIRE_CORE_TOOLS=1` additionally require a nonempty installed core pack, a `doctor --full` current-byte and live zero-egress-smoke result, and matching static status evidence. The `--install-core-tools` bootstrap option enables that assertion automatically after all seven installations succeed.

## 5. Register a project and verify Treehouse

Copy the tracked template to a private configuration directory, edit it, and register the result:

```bash
mkdir -p "$HOME/.config/gate/projects"
cp templates/project.json "$HOME/.config/gate/projects/my-project.json"
# Edit metadata, repository, execution, delivery, security, and learning fields.

./bin/gate.mjs project register \
  --file "$HOME/.config/gate/projects/my-project.json" --json
./bin/gate.mjs project verify my-project --json
./bin/gate.mjs project list --json
```

The canonical record is stored at `GATE_HOME/projects/my-project.json`, with owner-only permissions on POSIX hosts. Identical registration is idempotent; changed content for an existing ID and duplicate repository identities are rejected. Local `file://` repository locators are stored as physical realpaths and later fail verification if they resolve elsewhere. There is no update or delete command in v0.1. `project show my-project --json` returns the entire private contract, including its repository URL and destination reference, while list, general status, and observer summaries omit those fields.

An interruption or ambiguous audit append, flush, or close error may leave `.registry.lock`, the contract, and a durable `.registry.pending` under `GATE_HOME/projects`. While either control exists, full project reads fail or report invalid/degraded status. Verify that no writer is active, hash the exact canonical contract bytes, and require the marker's project ID, event ID, transaction nonce, and contract SHA-256 to match the exact `project.registered` event target and transaction evidence reference. If that bound event is absent, remove the unaudited contract and controls before retrying; if it exists, remove only the controls and then verify the project. Treat conflicts and digest mismatches as unresolved. Never blindly delete these files or remove only the lock. [The operating model](operating-model.md#private-project-contracts) gives the ordered recovery procedure.

The workspace bridge runs only on Linux or WSL2. If `--install-upstreams` was not used, install the locked Treehouse 3.1.3 release through the verified lane. Then point the bridge at an existing main repository checkout:

```bash
./bin/gate.mjs upstream install treehouse --json
./bin/gate.mjs workspace status --repo "$HOME/src/my-project" --json
./bin/gate.mjs workspace lease \
  --repo "$HOME/src/my-project" \
  --task issue-123 \
  --branch gate/issue-123 \
  --base main --json
```

Lease acquisition is the only operation that invokes Treehouse. GATE calls the verified binary as `treehouse get --lease --json --no-fetch --branch BRANCH --lease-holder HOLDER [--base BASE]`; when `--base` is omitted, the repository's Treehouse configuration selects the base. GATE never invokes Treehouse `status`, `return`, `destroy`, `prune`, or `enter`. It also disables lazy fetch and every Git transport, so all required refs, objects, and blobs must already be local. The bridge supplies no Git credential helper, proxy, SSH agent, or network broker. Fetch the required data first through a separate reviewed workflow with explicit network and credential handling, then run the offline lease command.

Treehouse and Git receive a minimal environment with an empty private home and temporary directory rather than the interactive shell environment. GATE ignores the caller's `PATH` and resolves Git only from fixed trusted system locations. Workspace operations accept only a narrow reviewed allowlist of shared or per-worktree Git configuration keys with validated values; every unreviewed key fails closed. This excludes includes, filters, credential/SSH/proxy commands, diff/merge drivers, editors, pagers, and external protocols. Git LFS depends on `filter.lfs.*`, so LFS repositories cannot use this bridge until a reviewed adapter exists.

Local settings that redirect repository behavior, alter object lookup, or weaken change detection also block the bridge. This includes worktree/Git-directory and repository input-file overrides, commit graphs, `core.checkstat`, `core.ignorestat`, `core.trustctime`, `core.fsmonitor*`, and a non-false `core.bare`. On POSIX, configured `core.filemode` and `core.symlinks` values must be true. Repair and review the repository configuration before retrying.

GATE binds private Treehouse state to the physical clone, then creates one task-ID-hashed root exclusively for the lease. A task ID is never reusable, even if acquisition fails or the process is interrupted; choose a fresh ID for every new attempt. The registry has a lifetime ceiling of 511 retained task roots for each physical clone. At that ceiling, continue from a new physical clone or wait for a future mount-safe upstream lifecycle primitive. Do not delete retained roots to recover capacity.

`workspace status` never runs Treehouse. It stable-reads each clone and task binding, the exact version-4 state with one healthy lease, and the exact 32-byte owner-only state key. GATE verifies the seed-inventory HMAC and requires SHA-256 of the raw state and key bytes to equal the immutable completed binding. That HMAC authenticates only the seed inventory; the lease evidence also relies on the trusted `get` receipt and the raw-file digest binding. Treehouse 3.1.3 `status` can perform recovery and move user files, so it is not an inspection command for GATE roots.

Before invoking `get`, GATE durably writes a `pending` binding. The lease response supplies the workspace path and a 32-character lowercase hexadecimal lease ID. GATE checks that response against the direct state read, verifies the private-root location, Git operation locks, submodules, nested metadata, real index, full object integrity, zero unreachable objects, and a controlled checkout of the exact `HEAD`, then records the durable `workspace.leased` event. Only after that event receipt exists does GATE atomically publish the `complete` binding with the state/key and event digests and read the state again. Save the path, lease ID, and task name with the private task record. An interruption can leave a pending binding or an unbound durable lease; aggregate status reports it as unverified, and every retry uses a fresh task ID.

Once the exact workspace `HEAD` is present in the intended landed branch, stop its processes and verify it. `--repo` must point to the main worktree, and `--landed-ref` must exactly match the branch currently checked out there:

```bash
./bin/gate.mjs workspace verify \
  --repo "$HOME/src/my-project" \
  --path WORKSPACE_PATH \
  --task issue-123 \
  --lease 0123456789abcdef0123456789abcdef \
  --landed-ref main --json
```

Verification is nonmutating and retains the lease. It refuses a changed lease identity, active processes, in-progress operations, submodules, nested Git metadata, dirty real indexes, grafts, object or HTTP alternates, replacement refs, corrupt or unreachable objects, and a workspace that differs from the controlled checkout of its current `HEAD`. Git-confirmed ignored cache paths may remain in the main worktree, while every leased-workspace extra or ignored path fails. After repeating the object checks, GATE proves the exact `HEAD` is an ancestor of the checked-out main-worktree branch. This is local reachability evidence only, not provider, No Mistakes, or publication proof.

Never run any Treehouse command directly against a GATE root, including `treehouse status`, `return`, `destroy`, `prune`, or `enter`. Reproduced bind-mount races in Treehouse 3.1.3 can make destructive lifecycle operations alter or delete host data, and status recovery can move files. Use GATE's workspace commands only. Retained leases consume disk, cannot be reset or reused, and need a future mount-safe upstream integration. GATE makes no power-loss durability claim.

If `workspace status` returns phase `operation-lock-present`, it inspected no task or Git state. Do not decide that the lock is stale from its age or recorded PID, and do not remove it automatically; PID reuse, reboot, a missing process-start identity, and an orphan Treehouse or Git child all make that inference unsafe. Follow the exact clone-specific procedure in [Operation-lock recovery](operating-model.md#operation-lock-recovery), then rerun GATE status before any workspace mutation.

Treehouse worktrees are change isolation, not a security boundary. Same-user code can mutate the clone's shared common `.git`, including hooks, configuration, objects, and refs. Use a standalone clone or OS sandbox for unknown or hostile code. The bridge does not start Firstmate, Codex, or GNHF; invoke No Mistakes; land the branch; merge, deploy, or publish; or clean retained roots.

## Run a zero-network offline artifact analysis

The implemented offline lane accepts one lawfully supplied Windows PE and exposes only REA's fixed PE-resource inspection. It does not execute the input or accept arbitrary REA arguments. Install the locked upstream, then check that Linux/WSL2, Bubblewrap, and the managed REA runtime can be resolved:

```bash
./bin/gate.mjs upstream install rea-stable --json
./bin/gate.mjs analysis capability --json
```

The capability command performs cheap prerequisite-presence checks and launches `/usr/bin/true` through the real minimal Bubblewrap namespace shape. It proves that this host can create that shape at the time of the check, but deliberately avoids reconstructing or hashing the full managed REA npm tree. Register and verify the project first, then pass one exact absolute local path:

```bash
./bin/gate.mjs analysis manifest \
  --project my-project \
  --path "$HOME/private/client-installer.exe" \
  --minutes 15 --json
```

The command performs the full reviewed-lock integrity reconstruction, hashes the runtime files, and copies and hashes at most 512 MiB into private owner-only storage. Review the returned artifact and project digests, fixed adapter, zero-network and zero-request limits, runtime identities, private evidence references, 15-minute manifest expiry, and enforced and unavailable controls. Supply the exact `confirmationRequired` string from that response:

```bash
./bin/gate.mjs analysis run \
  --project my-project \
  --manifest MANIFEST_ID \
  --confirm "ANALYZE MANIFEST_ID MANIFEST_SHA256 OFFLINE" --json

./bin/gate.mjs analysis status --json
```

Private artifact snapshots are capped at 64 files and 2 GiB in aggregate. Status reports retained capacity and pending or expired manifests. Manifest creation, execution claims, and purge use the same owner-only lock, so malformed lock or input-storage state blocks mutation. Retire an abandoned, expired, or terminal artifact with the exact purge confirmation returned by manifest creation:

```bash
./bin/gate.mjs analysis purge \
  --project my-project \
  --manifest MANIFEST_ID \
  --confirm "PURGE MANIFEST_ID MANIFEST_SHA256 OFFLINE ARTIFACT" --json
```

Purge refuses active or unknown runs and removes only the digest-bound snapshot and an empty sandbox. It keeps the manifest, claim, run, purge receipt, and evidence. Evidence remains bounded per stream but does not yet have an aggregate retention quota.

Every manifest is one-shot. The launcher repeats the full managed-upstream reconstruction and rechecks its project, artifact, upstream, and runtime bindings; creates fresh user, PID, network, IPC, and UTS namespaces; drops all capabilities; clears the environment; mounts the runtime and artifact read-only; and captures bounded private evidence. A successful adapter result also records only loopback, no IPv4 route, zero capabilities, and `NoNewPrivs`. CPU and memory quotas, immutable same-UID protection for the managed REA installation or `GATE_HOME`, and syscall-level denial of Unix sockets are unavailable. Follow [the offline operating contract](operating-model.md#offline-static-artifact-analysis) and the [end-to-end penetration-testing workflow](pentest-workflow.md) before promoting any result.

A proprietary client or other proprietary artifact must be lawfully supplied by the operator and kept outside Git. Neither possession nor offline analysis authorizes downloading another copy, contacting the vendor, using its accounts, testing an updater, or resolving or connecting to embedded endpoints. Those observations remain private hypotheses until separately written authority and an exact active engagement cover the proposed contact.

## Run a supervised security tool

The generic execution lane requires Linux or WSL2 with `/proc` mounted, an installed catalog command discoverable on `PATH` whose `commandIdentity.genericLaneAdmission` is `path-discovery`, a receipt-bound `scope.environment: host`, and receipt-approved `gate-home` because raw evidence always lands there. Verified managed core runtimes remain blocked from this lane until reviewed workflow-phase adapters exist. The lane rejects container, rootless-container, VM, and remote-lab engagements because it does not create those environments. Add the exact tool ID, host environment, and data destination when creating the engagement:

Nmap is a planning example: `./bin/gate.mjs tool plan nmap --json` reports its requirements. It remains blocked from generic execution pending reviewed runtime admission, even if installed and engagement-approved.

For the runnable example, set `GATE_HOME` to your private runtime root and supply an authorized copied image at `$GATE_HOME/artifacts/sample.jpg`. Install a reviewed, exactly versioned ExifTool from its official source through the catalog's `native-os` lane; catalog presence does not install it. The ID and executable command are `exiftool`, risk class is `P0`, and its command identity is `pathDiscovery: command-name`, `genericLaneAdmission: path-discovery`. Put that executable on `PATH` and require `genericLaneEligible: true` from `./bin/gate.mjs tool plan exiftool --json`. Eligibility does not verify version, integrity, or provenance. The read-only `-json` operation below reads metadata; the generic lane has host access and does not provide the fixed offline lane's zero-egress isolation.

```bash
./bin/gate.mjs engagement new local-assessment \
  --targets "$GATE_HOME/artifacts/sample.jpg" \
  --actions observe \
  --tools exiftool \
  --environment host \
  --allowed-destinations gate-home \
  --basis owner
```

Complete the authorization, plan, No Mistakes record, and `APPROVE ID` receipt workflow in the [README](../README.md#active-security-workflow). The plan and receipt must cover the exact file, `observe`, `exiftool`, host environment, and `gate-home`. Then check the exact target/action and create one manifest. `--tool` selects the catalog executable; everything after `--` is its proposed argument array and must contain exactly one whole argument equal to `{{GATE_TARGET}}`:

```bash
./bin/gate.mjs engagement check local-assessment \
  --target "$GATE_HOME/artifacts/sample.jpg" --action observe --json

./bin/gate.mjs engagement manifest local-assessment \
  --target "$GATE_HOME/artifacts/sample.jpg" \
  --action observe \
  --tool exiftool \
  --minutes 10 \
  --requests 250 \
  --parallel 2 \
  --rate 5 \
  --tokens 1000 \
  --json -- -json "{{GATE_TARGET}}"
```

Read the returned `operation.argv0`, expanded `operation.argv`, target argument index, catalog risk class, executable path and observed SHA-256, expiry, declared bounds, and complete `enforcement` object. Inspect the owner-only manifest named by `manifestRef` for its receipt-bound `gate-home` destination, private sandbox, and stdout, stderr, and result references. `declared-action-label-binding` records only a receipt-bound label; `argv-action-semantics-validation` is unavailable. Review whether the exact arguments implement that action, because only a reviewed adapter validates tool-specific flag semantics. The operator must provide the returned exact confirmation string before launch:

```bash
./bin/gate.mjs engagement exec local-assessment \
  --manifest MANIFEST_ID \
  --confirm "EXECUTE MANIFEST_ID MANIFEST_SHA256 UNMETERED" \
  --json
```

The manifest is one-shot and remains consumed after success, failure, interruption, or an ambiguous launch. In another terminal, request termination of one run or revoke the full engagement:

```bash
./bin/gate.mjs engagement stop local-assessment --run RUN_ID --json
./bin/gate.mjs engagement revoke local-assessment \
  --confirm "REVOKE local-assessment" --json
```

Stop and revocation are durable requests, but only the live original `gate engagement exec` supervisor polls and acts on them. Wall-duration handling and process-group termination have the same dependency. A supervisor crash or `SIGKILL` has no takeover path and can leave the ordinary tool process group alive.

GATE launches the opened, hashed executable descriptor through `/proc/self/fd` with no shell, empty stdin, a fresh process group, a minimal environment, and private `HOME`, `TMPDIR`, sandbox, stdout, stderr, and result records. It rechecks descriptor metadata immediately before spawn. The launch still runs as the operator's UID on the host. The child may read or change anything that identity can access, reach any route available to the host, obtain credentials through accessible files or local services, load mutable dependencies or configuration, and create processes outside the group GATE can supervise. `supervisor-crash-containment`, daemon-escape containment, and `immutable-executable-snapshot` are unavailable. `executable-descriptor-observed-sha256` records bytes read through the opened descriptor, but a same-UID writer can mutate a writable inode before or during exec, so the digest does not prove atomically frozen or launched bytes or trusted provenance. Request, rate, concurrency, and token values are receipt-bounded declarations; the generic lane does not measure them. Arbitrary argv may exceed the declared action label, so execution events use the maximum of its action effect and the catalog risk ceiling for conservative audit visibility; this does not block launch. If process-group authentication is lost during teardown, GATE records status `unknown` with termination reason `supervision-lost` instead of claiming termination. Use a reviewed adapter or a lane that implements the approved isolated environment when the operation depends on those controls.

## Optional Docker provider

Install Docker Desktop on Windows only when a selected tool profile needs OCI. Enable its WSL integration for Ubuntu, then verify from WSL:

```bash
docker version
docker compose version
docker info
```

Docker is useful for reproducible command-line dependencies. Native Windows installs remain the correct lane for Wireshark/Npcap capture, Windows trust-store interception, Burp's desktop UI, Sysinternals, WinDbg, USB/ADB, GPU tools, and radio hardware.

A container is not a security boundary once it receives host networking, raw devices, broad capabilities, privileged mode, or the Docker socket. GATE must display and record those effects before using such a profile.

## Native security-tool bridge

Install host-integrated tools from their official distribution channels. At minimum, the first Windows security profile should expose:

- Wireshark and TShark with Npcap for host traffic capture and saved-capture analysis;
- OWASP ZAP as the open-source intercepting proxy and scanner;
- Burp Suite as an optional user-licensed provider;
- Sysinternals and WinDbg for Windows process, filesystem, and debugger evidence;
- Android platform tools when a mobile engagement needs USB or ADB.

The target design treats each native program as a provider: a probe records its executable path and version, and an adapter supplies explicit arguments and evidence destinations. v0.1 verifies the exact bytes and version smoke of seven managed core runtimes, while other catalog entries have metadata and filesystem-only executable discovery. Compatible Linux/WSL2 PATH commands can use the supervised generic lane only when the catalog permits PATH discovery for that command identity. A `reviewed-admission` PATH entry remains `identity-unverified` and blocked even when a namesake is present. This prevents Python HTTPX from being mistaken for ProjectDiscovery httpx; the exact managed ProjectDiscovery release is byte-verified but also invocation-blocked until a workflow-phase adapter exists. Broad REA commands remain outside the fixed offline adapter. Native Windows and host-specific GUI or hardware paths still need a reviewed adapter or an operator-run step with bounded evidence. Do not add an entire installation directory to prompts or grant an agent an unrestricted shell merely because the program is installed.

Kali can be added later as a named WSL distribution or pinned container image. It is a compatibility toolbox, not GATE's version source. The catalog and lock records remain authoritative for the tools an agent may select.

## Cloud environment

Codex cloud is suitable for repository edits, tests, builds, static analysis, and offline evidence processing when the selected image provides the required CLIs. Run the preflight on each image rather than assuming Node, npm, GitHub CLI, Codex CLI, Python, Bubblewrap, `prlimit`, or Docker is present. The base bootstrap and tests can use a worker-local writable `GATE_HOME` such as `/tmp/gate`. `analysis capability` performs cheap file-presence checks and a real minimal Bubblewrap namespace launch; manifest creation and execution perform the expensive managed-REA integrity reconstruction and runtime hashing. A worker can expose `/usr/bin/bwrap` while blocking unprivileged user namespaces, so a real namespace smoke remains required. Report managed core activation as unavailable when that launch fails; do not replace it with an unsandboxed version command.

Managed cloud workers may lack raw sockets, packet interfaces, debugger attachment, USB devices, kernel capabilities, and unrestricted target routing. In v0.1, `gate doctor --full` reports the OS, architecture, WSL detection, repository validation, managed-runtime counts and a live smoke result for every installed locked runtime, presence-only results for other optional executables, visible non-loopback interfaces, Linux `CAP_NET_RAW` and `CAP_NET_ADMIN`, Yama `ptrace_scope`, `/dev/bus/usb` presence, and whether the default Linux Docker socket path exists. It deliberately leaves Docker-engine reachability unprobed and does not execute unmanaged optional tools. Those facts do not prove that debugger attachment, a specific capture, USB hardware, Docker, or target routing works. They also do not make generic execution egress-restricted: target-argument binding cannot prevent redirects, plug-ins, child processes, or the tool itself from contacting other systems. Probe the exact required capability before planning work and record an unavailable result when it cannot run. Live capture, interception of Windows applications, device analysis, and low-level active testing should remain on a deliberately configured laptop or lab until a narrow provider exists.

Example cloud smoke run:

```bash
export GATE_HOME=/tmp/gate
./scripts/bootstrap.sh
```

## Troubleshooting

If bootstrap reports an authentication failure, repair it directly and rerun:

```bash
gh auth login
codex login
export GH_TOKEN="$(gh auth token)"
```

If the dashboard does not open from Windows, confirm it is listening inside WSL and retry the loopback address:

```bash
curl http://127.0.0.1:4173/api/status
```

If Docker commands exist but `docker info` fails, start Docker Desktop and confirm WSL integration for the selected distribution. Docker remains optional for base GATE operation.

If a tool is missing, inspect its catalog plan before installing it:

```bash
node ./bin/gate.mjs tool plan TOOL_ID --json
```

Use the catalog's installation lane. Record any setup failure or compatibility workaround as a cause-to-change learning before promoting it into the shared defaults.

For one of the seven locked core tools, distinguish an absent runtime, receipt-only state, byte drift, and a smoke failure with the managed commands:

```bash
./bin/gate.mjs tool list --profile core --json
./bin/gate.mjs tool plan TOOL_ID --json
./bin/gate.mjs tool verify TOOL_ID --json
```

Reinstall only after reviewing the plan. A proxy-configured release download uses protected system `curl` with bounded manual redirects restricted to the reviewed GitHub release hosts; direct downloads use the same HTTPS host allowlist and redirect ceiling. Do not disable TLS or change a locked digest to make a download pass. For publication rollback, removal recovery, lock contention, and crash cleanup, follow the [managed-runtime recovery guidance](security-tooling.md#managed-core-runtime).

If `analysis capability` reports Bubblewrap or `rea-stable` unavailable, install the missing system package or managed upstream and rerun capability:

```bash
sudo apt install --yes bubblewrap
./bin/gate.mjs upstream install rea-stable --json
./bin/gate.mjs analysis capability --json
```

If capability fails its namespace probe, the host or cloud worker does not currently support this lane. Record it as unavailable and use a deliberately configured Linux/WSL2 host; do not substitute an ordinary host REA command and describe it as zero-network. If a later manifest or execution fails after capability passed, treat the runtime as changed or the stronger integrity/binding check as failed and inspect that evidence. A consumed manifest is never retried; create a new manifest after the runtime is repaired.

If a workspace command reports that Treehouse is absent or not integrity-verified, reinstall it through the managed lane and inspect status before retrying:

```bash
./bin/gate.mjs upstream install treehouse --json
./bin/gate.mjs upstream list --json
./bin/gate.mjs workspace status --repo "$HOME/src/my-project" --json
```

Do not substitute a `treehouse` found elsewhere on `PATH` or invoke Treehouse directly against a GATE root. Workspace operations intentionally resolve only the executable whose release archive and executable hashes match the reviewed lock, and they use fixed trusted system Git locations. Native Windows is unsupported; run the bridge inside WSL2. If a task root already exists, inspect it through GATE aggregate status and choose a fresh task ID rather than deleting or reusing the root.
