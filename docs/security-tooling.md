# Security tooling

GATE describes security tools through a reviewed catalog instead of installing an unbounded tool collection onto the laptop. “Cataloged” means that GATE knows the official source, license, compatible hosts, installation lane, executable, privilege needs, and approval boundary; it does not mean installed or admitted. In v0.1 the operator explicitly installs tools, while GATE directly installs only its small managed-upstream subset. A catalog tool becomes usable through GATE only after its pinned artifact and adapter pass review and a smoke test.

The machine-readable source of truth is [`catalog/security-tools.json`](../catalog/security-tools.json). It contains more than one hundred representative tools across web and API testing, network analysis, identity and exploitation, reverse engineering, mobile, DFIR, OSINT, cloud and Kubernetes, source security, fuzzing, and wireless or radio work. Profile files under [`config/profiles`](../config/profiles) select coherent subsets.

## Action classes

The catalog assigns the highest normal effect class exposed by each entry. A wrapper may expose a lower-risk mode, but it may never silently treat a higher-risk mode as lower risk.

| Class | Meaning | Required approval |
| --- | --- | --- |
| `P0` | Offline analysis of supplied source, files, captures, images, or hashes | Normal data policy; no target contact |
| `P1` | Passive public-source collection or local observation that does not contact a target | Declared evidence source and normal data policy |
| `A1` | Live observation or low-impact DNS, HTTP, TLS, service, API, or asset enumeration | No Mistakes review, exact-plan operator receipt, per-command scope check, and a reviewed execution adapter |
| `A2` | Fuzzing, injection probes, credential checks, interception, protocol mutation, or host changes | All `A1` requirements plus technique-specific limits |
| `A3` | Exploitation, poisoning, C2, credential dumping, deauthentication, destructive cloud actions, or persistence | All `A1` and `A2` requirements plus a controlled environment and explicit high-impact limits |

GATE can investigate a hypothesis, identify an attack path, prepare commands, and propose a deeper test without an active-operation receipt. It cannot turn curiosity into authority. An engagement envelope supplies targets, allowed action classes, accounts, rates, time window, exclusions, data rules, and stop conditions. Changing the target or material action invalidates the receipt.

Some suites span several classes. For example, Wireshark can analyze a saved capture as `P0`; capturing a live interface is active work whenever it observes target traffic and therefore needs an engagement even if catalog metadata uses `P1` for the executable's ordinary risk. Sqlmap detection is normally `A2`, while extracting data or invoking an operating-system shell is `A3`. The catalog risk label is planning metadata. The engagement policy controls target contact, and a wrapper may never use a lower catalog label to bypass it.

## Profiles

| Profile | Purpose |
| --- | --- |
| `default` | Low-risk local engineering and offline security analysis |
| `pentest` | End-to-end authorized application and infrastructure assessment |
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

Profiles are additive selections, not authority grants. Selecting `pentest`, `identity`, `radio`, or `lab` makes catalog entries discoverable and eligible for installation planning; v0.1 does not automatically install them, and the engagement and adapter gates still apply.

## Installation lanes

GATE keeps upstream projects external and defines the following installation lanes. In v0.1 only the managed npm and verified-release upstream lanes are implemented by `gate upstream install`; the remaining lanes are reviewed target designs for future per-tool adapters:

- `native-os` is for tools that need a GUI, packet capture, raw networking, a certificate store, a GPU, USB, radio hardware, or kernel integration. Typical examples are Wireshark, Nmap, ADB, Hashcat, and wireless tools.
- `pinned-release` installs a named upstream release artifact after checking its digest and signature when available. This is the preferred lane for Go, Rust, and self-contained binaries.
- `isolated-python` gives each Python tool its own locked `uv` environment. Tools never share an unrestricted global environment.
- `isolated-node` gives each Node tool a separate pinned dependency tree.
- `java-archive` installs a checksum-verified upstream archive for tools such as Ghidra, JADX, and Apktool.
- `oci` runs a digest-pinned service or heavy tool stack. Rootless operation is preferred, with explicit volumes and networks.
- `source-build` is used when the project does not publish a suitable artifact. The compiler, source commit, dependencies, and resulting digest must be recorded.
- `hardware` marks a tool that also needs a named supported device and firmware.
- `external-user-install` is reserved for software such as Burp Suite that the operator installs and licenses outside GATE.

The target admission record for every resolved installation contains the exact version, full source commit, platform, provider, artifact URL, digest, signature result, license hash, install time, and smoke-test result. v0.1 has exact records for its managed upstreams but no general per-tool admission store, so other catalog entries remain candidates. Branch names, floating tags, `latest` images, and abbreviated commits are not lock values.

Kali Linux is an optional compatibility toolbox rather than GATE’s package source of truth. A Kali image changes continuously and includes packages under many licenses. A future Kali profile must build a named package subset, pin the resulting image digest, record an SBOM, and recreate the image instead of updating it in place. No such profile ships in v0.1; dedicated catalog entries remain authoritative.

## Laptop execution

The control plane, Codex, and lightweight tools can run directly on the laptop; the other named upstreams must first be installed and integrated. Large or conflicting user-space stacks may run in rootless containers after a pinned profile exists. The target architecture uses a narrow local capability broker for packet-capture handles, raw sockets, certificate-store changes, device access, and similar privileges. v0.1 does not implement that broker, so an operator must run and document native privileged steps.

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

## Adapter contract

This is the admission contract for a future tool-specific adapter, expressed as a small manifest and wrapper rather than a copy of the upstream implementation. Arbitrary active execution is disabled in v0.1; catalog entries without a reviewed adapter and immutable tool lock remain candidates. Each admitted adapter must:

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
