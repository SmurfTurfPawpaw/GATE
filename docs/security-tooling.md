# Security tooling

GATE describes security tools through a reviewed catalog instead of installing an unbounded tool collection onto the laptop. “Cataloged” means that GATE knows the official source, license, compatible hosts, installation lane, executable, privilege needs, and approval boundary; it does not mean installed or admitted. Readiness is explicit: `candidate` has metadata only, `discovered` is a command accepted from `PATH` without version or integrity proof, `identity-unverified` is a PATH namesake that policy refuses to identify as the catalog product, receipt-only states record install evidence without current runtime proof, `managed-verified` has passed current-byte and live-smoke verification against a reviewed lock, and `adapter-ready` also has an available reviewed adapter. Managed verification establishes byte provenance, not invocation admission. Reusable execution admission also requires declared dependencies and privileges plus a reviewed workflow-phase adapter or another explicitly admitted lane.

The catalog's optional `commandIdentity` separates name discovery from execution admission. Missing metadata resolves to `reviewed-admission`, so a PATH namesake cannot become executable by omission. `pathDiscovery` records whether a command name is ordinary or ambiguous. `genericLaneAdmission: path-discovery` is an explicit exception for a small reviewed set of unambiguous, single-command CLIs; it allows a compatible Linux/WSL2 PATH candidate into the separately approved supervised generic lane while known-good provenance remains false. `genericLaneAdmission: reviewed-admission` records the candidate for diagnostics, withholds it as the executable, and keeps `genericLaneEligible` and `broadCapabilityReady` false. Service stacks, multi-command suites, GUI and hardware tools, commands with external data packs, and broad active tools retain reviewed admission. An ambient `httpx` command is blocked because the unrelated Python HTTPX client publishes the same name. The exact managed ProjectDiscovery HTTPx runtime can become adapter-ready for one reviewed GET operation; no PATH namesake or broader HTTPx surface is admitted. REA's fixed offline adapter likewise does not admit its broader A2 surface.

`tool list --profile core` does not execute a process, perform network access, or rerun a managed-runtime smoke. It validates the seven release locks and receipt bindings but reports an installation as receipt-only until an explicit plan or verification runs. Broader `tool list` inventory retains existing adapter capability probes: REA, for example, checks its fixed adapter prerequisites and launches a minimal Bubblewrap namespace probe before it can report `managed-receipt`, while integrity and adapter readiness remain false. Explicit `tool plan ID` performs full verification for an installed managed release or managed REA upstream. A successful REA plan exposes only execution mode `offline-static-pe-resources`; generic and broad REA execution remain blocked.

The machine-readable source of truth is [`catalog/security-tools.json`](../catalog/security-tools.json). It contains more than one hundred representative tools across web and API testing, network analysis, identity and exploitation, reverse engineering, mobile, DFIR, OSINT, cloud and Kubernetes, source security, fuzzing, wireless or radio work, and AI system testing. Profile files under [`config/profiles`](../config/profiles) select coherent subsets.

## Action classes

The catalog assigns the highest normal effect class exposed by each entry. A wrapper may expose a lower-risk mode, but it may never silently treat a higher-risk mode as lower risk.

| Class | Meaning | Required approval |
| --- | --- | --- |
| `P0` | Offline analysis of supplied source, files, captures, images, or hashes | Normal data policy; no target contact |
| `P1` | Passive public-source collection or local observation that does not contact a target | Declared evidence source and normal data policy |
| `A1` | Live observation or low-impact DNS, HTTP, TLS, service, API, or asset enumeration | No Mistakes review, exact-plan operator receipt, per-command scope check, and either a reviewed adapter or a separately confirmed one-shot generic manifest |
| `A2` | Fuzzing, injection probes, credential checks, interception, protocol mutation, or host changes | All `A1` requirements plus technique-specific limits and an execution lane whose available controls fit the plan |
| `A3` | Exploitation, poisoning, C2, credential dumping, deauthentication, destructive cloud actions, or persistence | All `A1` and `A2` requirements plus a deliberately controlled environment, explicit high-impact limits, and independent command review |

GATE can investigate a hypothesis, identify an attack path, prepare commands, and propose a deeper test without an active-operation receipt. It cannot turn curiosity into authority. An engagement envelope supplies targets, allowed action classes, accounts, rates, time window, exclusions, data rules, and stop conditions. Changing the target or material action invalidates the receipt. The [end-to-end penetration-testing workflow](pentest-workflow.md) maps this progression from authority and local evidence through network, application, exploitation, cleanup, retest, and reporting; the workflow itself grants no authority.

Some suites span several classes. For example, Wireshark can analyze a saved capture as `P0`; capturing a live interface is active work whenever it observes target traffic and therefore needs an engagement even if catalog metadata uses `P1` for the executable's ordinary risk. REA's broad catalog ceiling remains visible, while the implemented fixed PE-resource adapter is a narrower `P0` operation because it has no target contact and cannot execute arbitrary REA commands. SearchSploit is `P0` because its catalog command searches and copies from a pinned local database; compiling or executing a selected proof of concept is a separate `A3` operation. Nmap, Nuclei, Scapy, and active radio suites carry `A3` ceilings because their full command surfaces expose exploit, code, spoofing, poisoning, transmission, emulation, or injection modes. A reviewed adapter may expose a narrower mode while retaining that ceiling in the plan. The engagement policy controls target contact, and a wrapper may never use a lower catalog label to bypass it.

## Profiles

| Profile | Purpose |
| --- | --- |
| `default` | Low-risk local engineering and offline security analysis |
| `core` | Seven exact managed releases for discovery, resolution, HTTP probing, crawling, bounded port discovery, content discovery, and template-engine installation |
| `pentest` | Complete candidate set mapped by the end-to-end authorized assessment workflow |
| `blue-team` | Detection, endpoint visibility, incident response, and evidence analysis |
| `web` | Web, browser, and API testing |
| `network` | Discovery, packet capture, traffic analysis, IDS, and vulnerability scanning |
| `identity` | Directory, authentication, password auditing, and post-exploitation |
| `reverse-engineering` | Binary, firmware, emulation, debugging, and exploit-development analysis |
| `mobile` | Android and iOS static, device, instrumentation, and dynamic analysis |
| `dfir` | Disk, memory, timeline, host, and event-log forensics |
| `osint` | Public-source and external asset discovery |
| `cloud` | Cloud, container, Kubernetes, IaC, SBOM, and runtime posture |
| `source-security` | Static analysis, secrets, dependencies, and bounded fuzzing |
| `radio` | Hardware-dependent Wi-Fi, Bluetooth, Zigbee, RFID, and SDR work |
| `lab` | High-impact exploitation and adversary simulation |

Profiles are additive selections, not authority grants. Selecting `core` supplies one reviewed batch selector for managed runtime operations; selecting `pentest`, `identity`, `radio`, or `lab` makes broader catalog entries discoverable and eligible for installation planning. The engagement receipt plus reviewed-adapter or supervised-manifest gate still applies in every case.

## Managed core runtime

[`locks/tool-runtimes.lock.json`](../locks/tool-runtimes.lock.json) owns the exact reviewed GitHub-release versions and artifacts for the managed core.

Use `tool plan ID --json` to inspect the selected release and its remaining admission requirements.

The lock binds each tool to its exact catalog-entry digest, version, full 40-character source commit, release tag and evidence, checksum-manifest identity, artifact asset identity, URL and byte size, archive and executable SHA-256, exact archive member set, executable path, platform, and bounded smoke specification. It rejects floating references, missing bindings, unsafe member paths, links and devices, duplicate or case-colliding archive names, extra members, and catalog or byte drift. The 28 pinned artifacts cover Linux and macOS on x64 and ARM64. GitHub did not mark these observed releases immutable; six ProjectDiscovery source commits carried GitHub's verified status, while the FFUF source commit did not. The locked archive and executable hashes therefore remain the byte anchors, and every future update needs a new reviewed lock change.

`plan` accepts one tool ID. Each of `prefetch`, `install`, `verify`, and `remove` accepts either one tool ID or exactly one profile:

```bash
./bin/gate.mjs tool plan httpx --json
./bin/gate.mjs tool prefetch httpx --json
./bin/gate.mjs tool install --profile core --json
./bin/gate.mjs tool verify --profile core --json
./bin/gate.mjs tool remove httpx --json
```

`plan` shows the artifact, cache state, download and write effects, administrator/service/device requirements, exact smoke arguments, and limits without granting authority. `prefetch` downloads into the private content-addressed cache and checks the exact artifact size and SHA-256 without executing it. `install` inspects the exact archive, writes only the locked executable and receipt into a private staging tree, runs the smoke, and atomically publishes the runtime. `verify` checks the lock, catalog binding, exact two-file tree, receipt bindings, current executable size and SHA-256, and a new smoke whose output digest must match the installation evidence. `remove` atomically retires the runtime and receipt while retaining the content-addressed cache; the next reuse rechecks its exact size and SHA-256. Batch operations preserve all individual results and report partial completion as unresolved.

The default smoke supervisor is Linux/WSL2 only. It opens protected system Bubblewrap and `prlimit` paths directly, invokes no shell, creates fresh namespaces including a zero-network namespace, clears the environment, binds the exact tool and required system libraries read-only, supplies private temporary filesystems, and applies the process ceiling inside the new PID/user namespace. Each lock also bounds the argument list, wall duration, output bytes, process count, expected version substring, and `network: none`. The smoke does not independently cap memory, open file descriptors, or file size beyond its private temporary filesystems and host limits. macOS artifacts can be prefetched and hash-checked, but `install` and live `verify` cannot complete until a reviewed macOS zero-egress smoke sandbox exists. Native Windows has no pinned artifact in this lock.

All cache bytes, staging trees, installed binaries, and receipts stay under owner-only `GATE_HOME`. A receipt is evidence, not an admission anchor, and a same-user writer can replace it. `tool list --profile core` uses only schema- and binding-valid receipt evidence and withholds the managed executable; broader inventory can run existing adapter capability probes. Normal `status` and cockpit refreshes validate the receipt without hashing current executable bytes. They label it `receipt-only`, expose its last installation-smoke time and age, and explicitly set current verification false. Normal `doctor` hashes current bytes against installation-smoke evidence without executing the tool. `tool plan`, `tool verify`, and `doctor --full` rerun the live zero-egress smoke. Shared runtime-directory and artifact-cache audits tolerate a concurrently vanished entry only after confirming `ENOENT` (including a wrapped cause) and checking that the path is still absent; every present invalid entry still fails closed. A malformed or binding-mismatched receipt, changed executable, changed catalog entry, changed lock, extra installed path, or different live smoke output removes readiness on exact verification paths. Status and cockpit `unresolved` counts cover the full 126-entry catalog. The cheap receipt-only view still reports all core runtimes unresolved because it deliberately performs no current-byte or live-smoke verification; a full plan can report DNSx or HTTPx adapter-ready after that verification succeeds.

Install publication failures preserve or restore the previous runtime atomically. Removal atomically retires a runtime from its active path, but restoration after a deletion failure is best effort. On Linux, a process- and boot-bound mutation lock whose owner is definitively dead is reclaimed conservatively; an ownerless lock directory is reclaimed after a 60-second grace period. Non-Linux process ownership remains indeterminate. If a mutation lock remains indeterminate, prove no process still owns it rather than deleting it blindly. `SIGKILL` or power loss can still leave orphaned staging or `.previous-*` directories. They do not block future installs, but GATE does not yet reconcile them automatically; an operator must inspect and clean the exact owner-only paths under the private `GATE_HOME`. Linux/WSL2 transition serialization requires protected system flock and a retained owner-only regular file that is never removed during normal operations; kernel ownership releases on descriptor close or process death. Acquisition fails closed on contention; the current owner waits up to two seconds for the serialization flock when releasing its mutation lock. A release timeout fails closed rather than deleting another owner’s state. See the crash and concurrency regressions in [`test/tool-runtimes.test.mjs`](../test/tool-runtimes.test.mjs).

Materializing a runtime does not authorize target contact or admit invocation. Every lifecycle result states `installationGrantsAuthority: false` and `targetAuthority: engagement-receipt-required`. The generic lane refuses all seven managed runtimes. [`managed-adapters.json`](../config/managed-adapters.json) admits two narrower Linux/WSL2 paths after exact runtime verification: DNSx 1.3.1 performs one A query for one canonical domain through one literal resolver, and HTTPx 1.12.0 performs one GET for one canonical URL through one operator-approved literal IP. The HTTP compiler uses an IP URL for the socket destination, generates the approved authority as the Host header, supplies the approved DNS hostname as SNI for HTTPS, and repeats the IP in HTTPx's allowlist. HTTPx selects a certificate through SNI but does not validate certificate trust. Both adapters are limited to `observe` in `active-surface-validation`, compile fixed arguments from a closed typed operation, reserve one estimated request with concurrency one and rate at most two per second, require the engagement and workflow admission plus the returned exact execution confirmation, and keep raw output private. Redirects, request bodies, operator-supplied headers, authentication, headless operation, discovery expansion, raw arguments, and output files are unavailable. The other five managed core runtimes remain invocation-blocked pending their own reviewed adapters.

## Installation lanes

GATE keeps upstream projects external and defines the following installation lanes. In v0.1, `gate upstream install` implements the managed npm and verified-release orchestration upstreams, and `gate tool` implements the seven pinned-release core runtimes above. The remaining catalog lanes are reviewed target designs for future per-tool adapters:

- `native-os` is for tools that need a GUI, packet capture, raw networking, a certificate store, a GPU, USB, radio hardware, or kernel integration. Typical examples are Wireshark, Nmap, ADB, Hashcat, and wireless tools.
- `pinned-release` installs a named upstream release artifact after checking its digest and signature when available. This is the preferred lane for Go, Rust, and self-contained binaries.
- `isolated-python` gives each Python tool its own locked `uv` environment. Tools never share an unrestricted global environment.
- `isolated-node` gives each Node tool a separate pinned dependency tree.
- `java-archive` installs a checksum-verified upstream archive for tools such as Ghidra, JADX, and Apktool.
- `oci` runs a digest-pinned service or heavy tool stack. Rootless operation is preferred, with explicit volumes and networks.
- `source-build` is used when the project does not publish a suitable artifact. The compiler, source commit, dependencies, and resulting digest must be recorded.
- `hardware` marks a tool that also needs a named supported device and firmware.
- `external-user-install` is reserved for software such as Burp Suite that the operator installs and licenses outside GATE.

The target admission record for every resolved installation contains the exact version, full source commit, platform, provider, artifact URL, digest, available provider-verification evidence, license record, install time, and smoke-test result. v0.1 has exact records for its managed upstreams and seven managed release tools, but no general store for the other 119 catalog entries. Those entries remain candidates. Branch names, floating tags, `latest` images, and abbreviated commits are not lock values.

Executable identity alone does not make a ruleset, template collection, vulnerability database, feed, symbol pack, browser runtime, system image, benchmark, collector, corpus, or wordlist ready. Catalog `dataDependencies` records known external requirements and the required pin form. `dataDependencyReadiness: admission-required` means GATE has declared the dependency and has no reviewed lock proving that it is installed or current. Nuclei templates, the Exploit Database, capa and detection rules, Greenbone feeds, vulnerability databases, and Volatility symbols follow this rule. Runtime auto-update stays disabled. Operator-supplied rules, wordlists, corpora, schemas, and captures must be hashed and bound to the exact manifest even when no reusable pack is cataloged.

Arkime, BloodHound CE, Greenbone, MobSF, Sliver, Timesketch, and similar products need several services or executables. Impacket is a suite of separate entry points, and Kali is an environment. Their catalog `command` values are planning hints rather than proof of a runnable product. They remain `reviewed-admission` until a pinned stack or action-specific adapter verifies every component, service, data dependency, privilege, network, health check, and teardown step.

The catalog records reviewed CLI names, licenses, and canonical source repositories for the AI system candidates garak, Promptfoo, PyRIT, and Inspect AI. They remain candidate-only at `A2`. Admission must bind the exact model and endpoint, provider, credentials, probes or tasks, tools, prompt and token budgets, request rate, spend, content policy, data destinations, private evidence, and stop conditions.

Kali Linux is an optional compatibility toolbox rather than GATE’s package source of truth. A Kali image changes continuously and includes packages under many licenses. A future Kali profile must build a named package subset, pin the resulting image digest, record an SBOM, and recreate the image instead of updating it in place. No such profile ships in v0.1; dedicated catalog entries remain authoritative.

## Laptop execution

The control plane, Codex, and lightweight tools can run directly on the laptop. A compatible catalog command discovered on Linux or WSL2 may use the supervised generic lane after approval only when its command identity permits PATH discovery. The receipt must bind `scope.environment: host` and include `gate-home`, because raw evidence always lands there. PATH discovery does not vouch for the installation. The managed core separately vouches for exact executable bytes and a bounded version smoke; only the two reviewed DNSx and HTTPx operations above currently cross from verified runtime into active invocation. Large or conflicting user-space stacks may run in rootless containers after a pinned profile exists, but the generic lane does not implement container, rootless-container, VM, or remote-lab receipts. The target architecture uses a narrow local capability broker for packet-capture handles, raw sockets, certificate-store changes, device access, and similar privileges. v0.1 does not implement that broker, so an operator must run and document native privileged steps.

The offline-analysis lane exposes only the fixed REA PE-resource operation on Linux/WSL2 and does not consume an engagement receipt. See the [offline-analysis operating procedure](operating-model.md#offline-static-artifact-analysis) for capability checks, manifest and execution verification, isolation, retention, and unavailable controls.

An artifact's contents never grant scope. A proprietary client or other proprietary binary must be lawfully operator-supplied and stays private under `GATE_HOME`. Names, URLs, certificate subjects, and update endpoints extracted from it remain unverified offline hypotheses. Vendor or third-party contact requires independent ownership resolution and the active-engagement path.

Containers isolate dependencies, but they are not a security boundary after granting host networking, `NET_ADMIN`, raw devices, `--privileged`, or the Docker socket. WSL2 also cannot reliably provide Wi-Fi monitor mode, packet injection, or every USB radio. Those operations need compatible hardware on native Linux or a deliberately configured hardware environment. GATE must report “unsupported on this host” rather than pretending a command succeeded.

A virtual machine is not required for ordinary GATE use. Malware execution, C2 exercises, untrusted exploit code, and destructive lab scenarios should move to an optional repeatable lab only after a person can run its lifecycle without an AI. The following is the planned contract and is not implemented in v0.1:

```text
gate lab init
gate lab up
gate lab smoke
gate lab reset
gate lab down
```

The same inputs must recreate the image and tool versions, and reset must remove the test state.

## Execution lane contracts

The implemented fixed offline adapter follows the [offline-analysis operating contract](operating-model.md#offline-static-artifact-analysis). Its project binding supplies provenance, not target authority. Promotion to live work uses the `local-to-network-hypothesis` handoff in the [end-to-end workflow](pentest-workflow.md).

A reviewed tool-specific adapter is the normal admission path. It is expressed as a small manifest and wrapper rather than a copy of the upstream implementation. Each admitted adapter must:

1. Validate targets against the engagement envelope before launching a process.
2. Show the exact target, technique, estimated traffic, privilege, mutations, rate, timeout, and stop conditions during preflight.
3. Invoke an argument array without a shell and reject unrecognized flags.
4. Set time, process, file-size, concurrency, and network limits.
5. Support cancellation and terminate the complete process group.
6. Preserve original output and artifacts while parsing structured formats such as JSON, XML, SARIF, or PCAP.
7. Record the tool version, executable or image digest, redacted command, scope digest, timestamps, exit status, evidence hashes, limitations, and unresolved questions.
8. Treat target responses, web pages, captures, archives, extracted files, and tool output as untrusted data rather than instructions.
9. Keep credentials, recovered secrets, packet payloads, private binaries, and personal data out of prompts and ordinary logs.
10. Report command time, requests, bytes, and targets separately from model token usage. Missing token data is `unavailable`, never zero.

Tool-native output remains authoritative evidence. Parsed findings should link back to byte-addressable artifacts and label claims as observed, inferred, or unverified.

The supervised generic lane is the deliberate fallback for a compatible catalog command discovered on Linux or WSL2 before a tool-specific adapter exists. A PATH candidate is accepted only when `commandIdentity.genericLaneAdmission` permits `path-discovery`; it remains `discovered` and does not create a trusted artifact record. Managed core runtimes do not enter this fallback: a verified candidate reports one of the managed verification admission-required states and the `workflow-phase-admission-unavailable` constraint, with additional privilege or data blockers where applicable. For eligible PATH commands, the engagement must list the exact tool ID, bind `scope.environment: host`, and approve `gate-home` as an allowed destination because raw evidence always lands there; each launch follows this separate contract:

1. `gate engagement check` binds the current plan, envelope, receipt bytes, authorization expiry, host environment, exact target, declared action label, and permitted tools. The label is not a semantic analysis of the command.
2. `gate engagement manifest` accepts bounds within the receipt plus the selected tool's complete argument array containing exactly one whole-argument `{{GATE_TARGET}}`; the stored array contains the expanded target at its bound index, while `argv0` identifies the catalog command.
3. GATE resolves the eligible catalog command without running a locator, binds its catalog risk class, opens and hashes the regular executable, and records descriptor identity. It rechecks descriptor metadata immediately before spawn. `executable-descriptor-observed-sha256` is the bytes read through the opened descriptor; a same-UID writer can mutate a writable inode before or during exec, so the digest does not prove an atomically frozen launched byte snapshot, known-good origin, or the safety of interpreters, libraries, plug-ins, configuration, or inputs.
4. The operator reviews the immutable operation, catalog risk class, exact argv, and every control tier, including whether those arguments match the declared action. Only a reviewed adapter validates tool-specific flag semantics. The operator then supplies the exact `EXECUTE MANIFEST_ID MANIFEST_SHA256 UNMETERED` confirmation. A durable exclusive claim makes the manifest one-shot before spawn.
5. GATE launches the open descriptor through `/proc/self/fd` with `shell: false`, an empty stdin, a fixed minimal environment, a fresh process group, a private working sandbox, and bounded private stdout, stderr, and result records. Polling and termination operate only while that original supervisor remains alive.

The manifest reports the following truthfully:

- **Enforced:** engagement and host-environment binding, receipt-bound allowed destinations including `gate-home`, target argument, `declared-action-label-binding`, tool allowlist and catalog risk binding, exact argv, no shell, `executable-descriptor-observed-sha256`, minimal environment, private stdout and stderr, one-shot claim, and declared bounds within the receipt.
- **Best effort:** authorization, revocation, and stop polling; wall duration; and process-group termination, all requiring the original supervisor to remain alive.
- **Unavailable:** `argv-action-semantics-validation`; egress-target restriction; request count, request rate, tool concurrency, and token measurement; daemon-escape containment; `supervisor-crash-containment`; `immutable-executable-snapshot`; filesystem isolation; credential brokering; complete tool-artifact inventory; and known-good executable provenance.

`declared-action-label-binding` is not `argv-action-semantics-validation`, and target-argument binding is not egress enforcement. Arbitrary flags may invoke behavior outside the chosen class; redirects, proxy or tool configuration, plug-ins, child processes, or the executable itself may contact other systems. GATE records the more severe of the declared action effect and the catalog risk ceiling in audit events, but this conservative classification does not block launch. Durable stop and revocation files have no takeover worker: a supervisor crash or force-kill can leave the ordinary process group running, and same-user processes may also leave that group. The child runs with the operator's UID and can access whatever that identity and host permit, including files and local services not named in its minimal environment. Use an admitted adapter or a lane that implements a separate host, container, VM, or controlled lab when the plan depends on a generic-lane unavailable guarantee.

## Admission and learning

A newly discovered tool enters GATE through an isolated evaluation:

1. Confirm the canonical source, maintenance state, and license at an exact commit.
2. Compare it with existing tools on task success, reproducibility, laptop compatibility, output quality, privilege, data exposure, and resource or token cost.
3. Choose an installation lane, pin the artifact, verify its integrity, and generate an SBOM where practical.
4. Classify effects, privileges, secrets, network behavior, target policy, evidence formats, and cancellation behavior.
5. Run a bounded smoke test in an approved local target or fixture.
6. Add the catalog entry, adapter, lock, profile selection where justified, and a public learning line.
7. Send the immutable change through No Mistakes before it becomes a normal capability.

The learning line uses the repository convention `cause → resulting change`. Detailed output and sensitive evidence remain under `GATE_HOME`. That directory is one local trust domain in v0.1, so its whole-root write permission belongs only to trusted operator processes; keep credential values in a separate secret store and expose task-specific evidence where possible. Learning may improve tool selection and defaults, but it cannot expand target scope or active-operation authority.

## Licensing notes

Calling an external executable does not make GATE a derivative of that executable, but redistribution can create obligations. The lock must preserve the exact license text and third-party notices for the pinned artifact.

Several useful entries need explicit labels:

- Nmap uses NPSL rather than a standard open-source license, so GATE installs it externally and does not vendor it.
- Volatility 3 uses the Volatility Software License.
- Impacket uses a modified Apache Software License 1.1.
- Nikto’s code is GPL, while its databases have additional redistribution terms.
- Android SDK and emulator components have mixed terms.
- Burp Suite is proprietary and optional. The operator supplies and licenses it; OWASP ZAP is the open-source default.
- A Kali toolbox has no single project license. Its SBOM and per-package notices are the license record.

The `openSource` field therefore describes the pinned upstream tool as a whole and does not imply that every optional dataset, plugin, rule pack, firmware file, or container layer has the same license.
