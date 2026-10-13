# Third-party software

GATE composes independent upstream projects and security tools. The [MIT license](LICENSE) applies to GATE's original code; every upstream, package, dataset, rule pack, firmware image, container layer, and externally installed tool retains its own terms.

The machine-readable authority for upstream selection is [locks/upstreams.lock.json](locks/upstreams.lock.json). It records full Git commits, release-artifact integrity, and, for npm lanes, the exact direct version plus the digest of a committed dependency lock under [locks/npm](locks/npm). If this document and the lock differ, stop the update and correct the reviewed lock and notice together.

## Orchestration and analysis upstreams

The following projects are referenced or installed externally; their source is not copied into GATE. License identifiers below were verified from the upstream repository license files. Links resolve to the locked source commits.

| Project | Locked revision | Version | License | Use in GATE |
| --- | --- | --- | --- | --- |
| [Firstmate](https://github.com/kunchenguid/firstmate/tree/7df545bf74ff729ed1733f77b0aea02a9b164ac1) | `7df545bf74ff729ed1733f77b0aea02a9b164ac1` | source | [MIT](https://github.com/kunchenguid/firstmate/blob/7df545bf74ff729ed1733f77b0aea02a9b164ac1/LICENSE) | Intake, supervision, and dispatch |
| [Treehouse](https://github.com/kunchenguid/treehouse/tree/20464a779bc30932d1dd4875886d916f4d4c28b3) | `20464a779bc30932d1dd4875886d916f4d4c28b3` | 3.1.3 | [MIT](https://github.com/kunchenguid/treehouse/blob/20464a779bc30932d1dd4875886d916f4d4c28b3/LICENSE) | Workspace leases |
| [GNHF](https://github.com/kunchenguid/gnhf/tree/f2ad5baff8de453bd4222e3d6ce53b43522b1fa2) | `f2ad5baff8de453bd4222e3d6ce53b43522b1fa2` | 0.1.51 | [MIT](https://github.com/kunchenguid/gnhf/blob/f2ad5baff8de453bd4222e3d6ce53b43522b1fa2/LICENSE) | Bounded iterative leaf tasks |
| [No Mistakes](https://github.com/kunchenguid/no-mistakes/tree/93b4407137efde476e6588fca809884afa543b9c) | `93b4407137efde476e6588fca809884afa543b9c` | 1.96.0 | [MIT](https://github.com/kunchenguid/no-mistakes/blob/93b4407137efde476e6588fca809884afa543b9c/LICENSE) | Review through PR and CI |
| [Lavish](https://github.com/kunchenguid/lavish-axi/tree/7cc7a4d91f0ac160a6ab42db90f2120c977afd01) | `7cc7a4d91f0ac160a6ab42db90f2120c977afd01` | 0.1.87 | [MIT](https://github.com/kunchenguid/lavish-axi/blob/7cc7a4d91f0ac160a6ab42db90f2120c977afd01/LICENSE) | Local planning artifacts |
| [AXI](https://github.com/kunchenguid/axi/tree/5a422752e6c4ce7d1af18bf56d36382374555d7d) | `5a422752e6c4ce7d1af18bf56d36382374555d7d` | 0.1.13 | [MIT](https://github.com/kunchenguid/axi/blob/5a422752e6c4ce7d1af18bf56d36382374555d7d/LICENSE) | Agent interface contract |
| [Skills CLI](https://github.com/vercel-labs/skills/tree/13e4063a1cf913f5606d57d42ab83a86f5001e04) | `13e4063a1cf913f5606d57d42ab83a86f5001e04` | 1.7.2 | [MIT](https://github.com/vercel-labs/skills/blob/13e4063a1cf913f5606d57d42ab83a86f5001e04/LICENSE) | Reviewed skill distribution |
| [REA stable](https://github.com/morluto/rea/tree/a56f7bb668ab23fec8d33f7af353ac7ed2fe1895) | `a56f7bb668ab23fec8d33f7af353ac7ed2fe1895` | 6.4.0 | [MIT](https://github.com/morluto/rea/blob/a56f7bb668ab23fec8d33f7af353ac7ed2fe1895/LICENSE) | Stable evidence analysis package |
| [REA edge](https://github.com/morluto/rea/tree/64041e3072e968002e2085445217ccde1f36e5d7) | `64041e3072e968002e2085445217ccde1f36e5d7` | 6.4.0+source.64041e30 | [MIT](https://github.com/morluto/rea/blob/64041e3072e968002e2085445217ccde1f36e5d7/LICENSE) | Newer source providers, evaluated separately |

An upstream's own dependency notices still apply. Before redistribution, packaging, or publication, preserve the exact license text and notices from the installed artifact rather than relying only on this summary.

## JavaScript runtime dependencies

The exact resolved tree and integrity values are in `package-lock.json`.

| Package | Version | License | Purpose |
| --- | --- | --- | --- |
| [ajv](https://github.com/ajv-validator/ajv) | 8.20.0 | MIT | JSON Schema validation |
| [ajv-formats](https://github.com/ajv-validator/ajv-formats) | 3.0.1 | MIT | Standard format validation for Ajv |

Transitive packages are listed in `package-lock.json` and retain their own licenses.

## Security-tool catalog

[catalog/security-tools.json](catalog/security-tools.json) is metadata for 122 tools; it is not a bundled distribution. Each entry records its canonical upstream, license label, open-source status, hosts, privileges, risk class, and possible installation lanes. Installing an entry creates a separate relationship between the operator and that upstream.

Some notable exceptions and mixed terms require deliberate handling:

- Burp Suite is proprietary, optional, and installed and licensed by the operator. OWASP ZAP is the open-source default.
- Nmap uses the Nmap Public Source License rather than a standard open-source license; GATE does not vendor it.
- Volatility 3 uses the Volatility Software License.
- Impacket uses a modified Apache Software License 1.1.
- Nikto's code and databases have distinct redistribution considerations.
- Android SDK and emulator components contain mixed terms.
- Kali Linux is a collection with per-package licenses, not a single redistributable tool. A GATE image needs a pinned package set, digest, SBOM, and notices.

Future tool adapters will call external executables while preserving upstream identity. No general security-tool execution adapter ships in v0.1. Vendoring, modifying, embedding, or redistributing a tool requires a separate license review. See [docs/security-tooling.md](docs/security-tooling.md#licensing-notes) for the catalog policy.

## Updating notices

An upstream or dependency update must change the exact lock, verify integrity and license, run its smoke test, update this notice when terms or versions change, record the cause-and-change learning, and pass No Mistakes review before adoption.
