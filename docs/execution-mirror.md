# Operational execution mirror

The operational mirror lets the operator follow one campaign and one supervised execution attempt while it is running, then inspect its retained ordered history. With the authenticated remote option enabled, the runner polls and projects active run state and the bounded output tail at roughly one-second cadence. This is a near-real-time structured projection, not byte streaming, a PTY, or a screen recording. It does not open a shell, accept command text, grant authority, or replace the private evidence files under `GATE_HOME`.

## Surfaces

| Surface | Mirror data |
| --- | --- |
| `https://gate.giovannicallebaut.com/` | Authenticated near-real-time projection supplied by the enrolled laptop runner when explicitly enabled |
| Loopback local companion | Current projection from the local observer |
| `https://smurfturfpawpaw.github.io/GATE/` | Same interface with synthetic example data and a link to the authenticated live cockpit |

The Pages build is always labelled **PUBLIC PREVIEW · NO LIVE DATA**. It never calls the live coordinator and never receives commands, output, targets, telemetry, or session capabilities. The authenticated personal domain is the authoritative remote surface.

## What the mirror means

Each selected campaign can expose up to eight recent attempts under opaque labels such as `Attempt 1`. GATE reserves that ordinal under a kernel-backed private sequence before publishing a new execution manifest, so the label stays attached to the attempt across refreshes, tied timestamps, backdated records, restarts, and later attempts. A failed publication may leave a harmless gap. Legacy manifests created before durable ordinals remain valid private history but are omitted from the mirror because assigning them a new label after the fact would be misleading. An attempt may contain:

- the operator-visible work order;
- the exact command after deterministic secret masking;
- a bounded tail of stdout and stderr;
- typed browser, tool, file, test, agent, system, and result events when a reviewed producer supplies them;
- queued, running, stopping, terminal, or blocked state;
- observed timestamps and elapsed time;
- determinate progress only when a producer supplies real completed and total counts;
- token, cost, request, retry, and tool-run measurements with provenance.

Every entry carries one fidelity label:

- `exact`: the displayed text matches the admitted projected value;
- `redacted`: deterministic masking changed one or more sensitive spans;
- `summarized`: the producer emitted an allowlisted summary rather than the complete source;
- `unavailable`: the producer could not safely or truthfully supply the value.

`truncated` means a documented display bound removed content. It is never presented as complete. Terminal control characters are escaped before projection. A line that still resembles a credential after masking is replaced as a whole with `[withheld: possible secret]`.

The initial mirror producer covers GATE supervised-execution manifests and run state. It reads at most the final 4 KiB from each stdout and stderr file, projects at most four combined output lines, and bounds displayed text to 240 characters per entry. It does not yet automatically observe arbitrary browser work, desktop terminals, Codex tool calls, files, tests, or subagents. Those channel names are reserved for later reviewed typed producers; their absence is shown as unavailable rather than inferred from conversation text.

Ordered entries show the retained history observed by the latest projection. While a supervised execution is active and the runner remains connected, the remote mirror refreshes that state and bounded tail concurrently at approximately one-second intervals. Transport, observer, storage, or browser latency may make an individual refresh later. The cockpit may say `Live` only while the source is connected and its freshness window is current; otherwise it identifies the view as retained, delayed, stale, disconnected, or unavailable.

Here, **concurrently** means that successive snapshots reopen the current run record and evidence tail while the supervised process is still running. New output, elapsed time, and running or stopping transitions can therefore appear before a result exists. A terminal result is appended only after the process finishes; it is not used to reconstruct or release the preceding updates.

The remote runner preserves the protocol's 128 KiB fleet-snapshot ceiling by pruning mirror history deterministically. It retains active and newest attempts first; when older history is omitted, the retained projection includes a summarized `system` entry with `truncated: true` instead of appearing complete.

The mirror never contains hidden chain-of-thought, system or developer instructions, raw credentials, private internal IDs, target selectors, raw evidence, private paths, unbounded logs, or a PTY. A masked command or bounded output line can still contain sensitive operational context, so mirror state remains private operator data and the coordinator database remains sensitive.

## Enable the remote projection

Remote command and output projection is off by default. Enable it only in the owner-only environment actually loaded by the intended runner. For a foreground runner, edit the generated case environment:

```sh
runner_state="${GATE_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/gate}/remote/example-case/runner"
runner_env="$runner_state/runner.env"
test -f "$runner_env" && test ! -L "$runner_env"
if grep -q '^GATE_REMOTE_EXECUTION_MIRROR=' "$runner_env"; then
  sed -i 's/^GATE_REMOTE_EXECUTION_MIRROR=.*/GATE_REMOTE_EXECUTION_MIRROR=1/' "$runner_env"
else
  printf '%s\n' 'GATE_REMOTE_EXECUTION_MIRROR=1' >> "$runner_env"
fi
chmod 0600 "$runner_env"
```

For the reviewed persistent user service, edit its installed environment copy instead. The systemd instance name is a local label and need not equal the case ID:

```sh
instance=live
runner_env="${XDG_CONFIG_HOME:-$HOME/.config}/gate/remote-runner-$instance.env"
test -f "$runner_env" && test ! -L "$runner_env"
if grep -q '^GATE_REMOTE_EXECUTION_MIRROR=' "$runner_env"; then
  sed -i 's/^GATE_REMOTE_EXECUTION_MIRROR=.*/GATE_REMOTE_EXECUTION_MIRROR=1/' "$runner_env"
else
  printf '%s\n' 'GATE_REMOTE_EXECUTION_MIRROR=1' >> "$runner_env"
fi
chmod 0600 "$runner_env"
systemctl --user restart "gate-remote-runner@$instance.service"
systemctl --user --no-pager --full status "gate-remote-runner@$instance.service"
```

Do not run a foreground runner and a systemd runner against the same journal. Confirm the active unit's `EnvironmentFile` before editing if a machine uses a different installation path:

```sh
systemctl --user cat "gate-remote-runner@$instance.service"
```

Reload the authenticated cockpit and verify all of the following before calling the mirror live:

1. the banner identifies the authenticated live surface;
2. the selected campaign shows `Mirror available` and a current attempt;
3. command and output entries carry fidelity and truncation labels;
4. a known secret-shaped local fixture is masked or withheld;
5. progress is indeterminate when no real count exists;
6. stopping the runner makes the projection stale or unavailable rather than leaving it live;
7. the Pages copy still says **PUBLIC PREVIEW · NO LIVE DATA** and shows only synthetic entries.

Set `GATE_REMOTE_EXECUTION_MIRROR=0` or remove the variable, then restart the runner, to disable command and output projection. The coordinator retains previously uploaded records according to its private database retention and backup policy; disabling future uploads does not erase already persisted data.

## Authority boundary

Mirror visibility follows execution; it never precedes or authorizes it. Engagement checks, reviewed adapters or manifests, exact operator receipts, target limits, stop conditions, and private evidence handling remain unchanged. A line displayed in the mirror proves only that the bounded producer observed and projected that line with the stated fidelity.
