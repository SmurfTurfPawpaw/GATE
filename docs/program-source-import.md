# Program source snapshots

GATE can retain a public program, lab, or intentionally vulnerable CTF rules
page as private evidence before a Program Profile or campaign is prepared. The
snapshot lane separates exact source bytes from a bounded metadata, scope, and
rules projection:

- the exact body is content-addressed under `GATE_HOME/program-sources` and is
  never returned by the snapshot API;
- the checked-in schema validates the source identity, acquisition metadata,
  scope claims, rule claims, locators, predecessor, and all three digests;
- each observation creates a revision, including a later observation of
  unchanged bytes, so freshness is preserved without duplicating the body;
- a revision diff reports only counts and change categories. It does not
  reproduce selectors, rule text, local paths, or source bytes;
- the source, projection, and full snapshot have separate SHA-256 identities.

The importer does not interpret a source as authorization. A projection is
source-backed candidate evidence for the private Program Profile workflow. It
does not confirm the operator's authority, complete an attestation, create an
engagement, start a workflow phase, or contact a target. Manual-only Program
Profile answers remain manual-only.

## Identities

Every `ProgramSourceSnapshot` records:

| Field | Meaning |
| --- | --- |
| `metadata.contentSha256` | SHA-256 of the exact retained response or file bytes. Use this when citing the exact source body. |
| `metadata.projectionSha256` | Canonical digest of only the bounded `scope` and `rules` projection. |
| `metadata.snapshotSha256` | Canonical digest of the full snapshot envelope except its own digest field. This freezes the source identity, acquisition metadata, projection, storage reference, and predecessor. |

A campaign grant that relies on the imported interpretation should bind all
three. A simple Program Profile source-ledger item uses the source ID and
`contentSha256`; `programProfileSourceFromSnapshot(snapshot)` produces that
schema-compatible object without reading the retained body.

## Local saved-source import

The first pilot should normally save a rules or scope page locally and import
that file. This keeps acquisition separate from profile preparation and makes
the exact reviewed bytes reproducible. The input must be a stable regular file
owned by the current user, must not be a symlink or hard link, must be no larger
than 2 MiB, and must stay outside the GATE repository. Its original local path
is deliberately omitted from retained metadata.

The operator-facing command accepts the source body and an optional private
projection file. Both files must stay outside the repository. The command
prints a bounded receipt with digests, acquisition metadata, and claim counts;
it never prints the body, local path, body reference, source notes, selectors,
or rule text.

```bash
./bin/gate.mjs source import training-ctf published-rules \
  --file /private/operator-input/rules.html \
  --type program-rules \
  --title "Published training challenge rules" \
  --reference https://ctf.example.test/rules \
  --media-type text/html \
  --projection /private/operator-input/rules-projection.json \
  --json
```

Omit `--projection` to snapshot the exact body with an empty candidate
projection. This can be useful when capture and interpretation are separate
review steps. It does not infer claims from untrusted text.

The library API is asynchronous so local and public-source acquisition share
one interface:

```js
import { runtimePaths } from "./src/lib/paths.mjs";
import { importProgramSource } from "./src/lib/program-sources.mjs";

const paths = runtimePaths();
const result = await importProgramSource({
  paths,
  programId: "training-ctf",
  source: {
    id: "published-rules",
    type: "program-rules",
    title: "Published training challenge rules",
    reference: "https://ctf.example.test/rules"
  },
  acquisition: {
    kind: "local-file",
    path: "/private/operator-input/rules.html",
    mediaType: "text/html"
  },
  projection: {
    scope: [
      {
        id: "challenge-web",
        selector: { type: "domain", value: "ctf.example.test" },
        disposition: "allowed",
        claimState: "observed",
        conditions: ["Use only the intentionally vulnerable challenge environment."],
        locator: { kind: "section", value: "Scope" }
      }
    ],
    rules: [
      {
        id: "automation-rule",
        category: "automation",
        disposition: "conditional",
        claimState: "observed",
        summary: "Automation is permitted within the published challenge limits.",
        conditions: ["Keep activity within the challenge host."],
        locator: { kind: "section", value: "Rules" }
      }
    ]
  }
});
```

The projection is explicit because arbitrary web text is untrusted input and a
generic parser cannot safely decide what grants authority or what an ambiguous
rule means. Each claim therefore has a stable ID, claim state, source locator,
and conditions. `unknown` claims must be `unverified`, and `conditional` claims
must state at least one condition. A later reviewed recommendation producer may
translate these claims into Program Profile proposals while preserving the
snapshot digests and locators.

## Bounded public URL retrieval

`kind: "public-url"` is available only when the caller passes
`allowNetwork: true`. Retrieval:

- accepts HTTPS on the default port, without credentials;
- rejects local, private, link-local, reserved, documentation, multicast, and
  mixed public/private DNS answers;
- pins one checked public address for the TLS connection and checks the peer;
- sends no cookies or authorization headers and requests identity encoding;
- follows at most three revalidated HTTPS redirects;
- applies one absolute 15-second deadline to DNS, redirects, and response reads;
- applies one cumulative 2 MiB budget to redirect bodies and the final body;
- stores response bytes and bounded response metadata privately.

This is passive source acquisition, but it is still a network request to the
source host. The campaign controller must use it only when that retrieval is
appropriate. Importing a program page never permits a subsequent request to an
asset named on that page.

The public command exposes that network decision as a required valueless
switch. Without `--allow-network`, it stops before DNS or HTTP activity:

```bash
./bin/gate.mjs source fetch training-ctf published-rules \
  --url https://ctf.example.test/rules \
  --type program-rules \
  --title "Published training challenge rules" \
  --projection /private/operator-input/rules-projection.json \
  --allow-network \
  --json
```

The canonical HTTPS request URL is also retained as the source reference.
Hostname case, an explicit default port, dot segments, and fragments therefore
cannot create a source identity different from the URL actually requested. The
fetch path does not accept cookies, credentials, authorization headers, a
non-default port, or an operator-selected private address.

## Revision and verification behavior

`readCurrentProgramSource(programId, sourceId, { paths })` revalidates the
contiguous predecessor chain, schema, projection digest, snapshot digest,
storage identity, exact current body length, and exact current body digest.
Each manifest is limited to 512 KiB and the complete readable manifest history
is limited to 16 MiB. Distinct retained bodies are limited to 64 MiB per source
and verified once per content digest while replaying the complete chain.
Mutation, missing bytes, an unexpected storage entry, an
interrupted lock, or a history/pointer mismatch blocks the read. A failure after
the first durable write retains the mutation lock for explicit local review
instead of making a partial revision look complete.

`diffProgramSourceSnapshots(previous, current)` returns revision numbers,
booleans for content, projection, and source-metadata changes, and aggregate
added/removed/changed/unchanged counts for scope and rules. Exact claims remain
in the private snapshot supplied by the local controller.

Those diff fields are the safe integration point for an observed source-change
KPI in the cockpit. The importer returns them to the local controller; it does
not publish dashboard state itself. A controller should preserve the categorical
change and counts, keep exact claims private, and trigger the campaign's
`source-binding-change` stop whenever the three grant-bound source digests no
longer match the verified current snapshot.

Operators can inspect the same bounded metadata and categorical diff without
opening private manifests:

```bash
./bin/gate.mjs source show training-ctf published-rules --json
./bin/gate.mjs source diff training-ctf published-rules --json
./bin/gate.mjs source diff training-ctf published-rules --from 1 --to 3 --json
```

The default diff compares the current revision with its immediate predecessor.
`show` and `diff` verify the complete contiguous manifest chain and the exact
retained body digests before returning. Neither command returns individual
projection claims or source bytes.

The source registry is shared because the Program Profile registry is shared.
Campaign execution state still belongs to one immutable case. A controller
must bind the selected snapshot digests into its campaign preparation record
before creating that case; a later source revision does not silently widen or
change an existing case.
