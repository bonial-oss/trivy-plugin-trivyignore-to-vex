# trivyignore-to-vex — Product Requirements Document

## Problem Statement

Trivy's `.trivyignore.yaml` provides a structured way to suppress vulnerability findings, but these exclusions remain invisible to broader vulnerability management workflows. Organizations adopting VEX (Vulnerability Exploitability eXchange) to communicate assessment decisions must manually recreate suppression rationale in VEX format. This duplication is error-prone, drifts over time, and prevents teams from leveraging VEX-aware tooling for findings they have already assessed.

## Product Overview

`trivyignore-to-vex` is a Trivy plugin that converts `.trivyignore.yaml` files into OpenVEX documents. It uses pattern-based inference to derive VEX status from existing statements, defaulting to `affected` (risk accepted) for unrecognized patterns. Author, document identity, and role can optionally be derived from a Backstage `catalog-info.yaml` file; CLI flags override the derived values and are also sufficient on their own.

**Repository:** `github.com/bonial-oss/trivy-plugin-trivyignore-to-vex`
**Language:** Go
**License:** Apache-2.0 (REUSE compliant)
**Copyright:** 2026 Bonial International GmbH

## Distribution Model

`trivyignore-to-vex` is delivered via a **dual-channel strategy**: as a Trivy plugin *and* as a standalone CLI (Homebrew + direct binary). The channels are complementary, not alternatives. The plugin identity is a *distribution channel*, not an architectural coupling — the tool has no runtime interop with Trivy (it reads a YAML file and writes a JSON file), so the plugin manifest is purely additive over the standalone binary (see NFR-1.1, NFR-1.2).

### Distribution channels

| Channel                            | Install command                                                          | Primary audience                                                 |
|------------------------------------|--------------------------------------------------------------------------|------------------------------------------------------------------|
| Trivy plugin                       | `trivy plugin install github.com/bonial-oss/trivy-plugin-trivyignore-to-vex`             | Existing Trivy users — direct discovery via the plugin index     |
| Homebrew                           | `brew install bonial-oss/tap/trivyignore-to-vex` *(tap TBD)*                | macOS/Linux developers using Homebrew as their package manager   |
| Direct binary (GitHub Releases)    | Download `.tar.gz` from Releases, place in `$PATH`                       | Air-gapped, containerised, or CI environments pinning archives   |

### Why also ship as a Trivy plugin

| Capability                                          | Benefit                                                                             |
|-----------------------------------------------------|-------------------------------------------------------------------------------------|
| `trivy plugin install …`                            | One-command install for the target audience without adopting a new package manager  |
| `plugin.yaml` platform manifest                     | Trivy resolves `os`/`arch` and fetches the correct release archive automatically    |
| `trivy plugin upgrade`                              | Version management delegated to Trivy                                               |
| `trivy trivyignore-to-vex …` sub-command               | Namespace next to `trivy image …` — muscle memory, CI-friendly                      |
| CI base-image governance                            | Teams already whitelist `trivy`; a plugin adds no new top-level binary to approve   |
| `aquasecurity/trivy-plugin-index` listing           | Discovery surface for the exact target audience                                     |

### What being a Trivy plugin does *not* provide

- **No shared runtime state**: no in-process API, no shared scan cache, no inheritance of `trivy.yaml`, registry auth, or log levels.
- **No scan-pipeline integration**: the generated OpenVEX file is consumed by a separate invocation. Whether the generator is a plugin or a standalone binary is invisible to that consumer.
- **No access to Trivy scan output**: the tool does not currently read Trivy's SBOM or scan cache to enrich product identifiers (see *Future Considerations*).

### Positioning: `.trivyignore.yaml` as interface, VEX consumed externally

Trivy already reads `.trivyignore.yaml` natively and consumes OpenVEX via `--vex`. Round-tripping through this tool inside a single Trivy invocation is therefore redundant — Trivy would suppress the same findings from the ignore file directly. The value materialises when the generated OpenVEX is consumed **outside** Trivy.

`.trivyignore.yaml` is the *interface*: developers edit it in-repo, PR-reviewed, colocated with the code that owns the vulnerabilities. The OpenVEX document is a *derived* artefact distributed to downstream consumers at build/release time — no dual maintenance.

Target external consumption patterns:

| Pattern                                    | How it flows                                                                                                     |
|--------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| **OCI referrer on a container image**      | Push VEX as an OCI artifact referring to the image digest (e.g. `oras attach` using the OCI 1.1 referrers API)   |
| **Container image attestation**            | Sign with `cosign attest --predicate openvex.json --type openvex` and store in the OCI registry                  |
| **Org-wide VEX repository**                | Publish to a Trivy `vex-repo` or equivalent OpenVEX repository ingested by every team's scan                     |
| **Cross-scanner consumption**              | Feed to Grype, OSV-Scanner, Dependency-Track — VEX-aware tools that do not read `.trivyignore.yaml`              |
| **Compliance / audit deliverable**         | Machine-readable, standard-shaped rationale for suppressed findings                                              |

### Dual-mode trade-offs

| Concern                        | Plugin + standalone (current)                                | Plugin-only                                    | Standalone-only                                              |
|--------------------------------|--------------------------------------------------------------|------------------------------------------------|--------------------------------------------------------------|
| Install channels               | plugin index + Homebrew + direct binary                      | plugin index only                              | Homebrew + direct binary only                                |
| Discovery                      | broad                                                        | Trivy audience only                            | generic channels only                                        |
| Coupling to Trivy              | distribution only (`plugin.yaml`, ~30 lines)                 | distribution only                              | none                                                         |
| Ongoing cost                   | track Trivy plugin manifest schema + maintain Homebrew tap   | track Trivy plugin manifest schema             | build/maintain per-platform packaging without plugin support |
| Air-gapped / non-Trivy users   | supported via Homebrew or direct binary                      | not supported                                  | supported                                                    |

The dual-channel design captures plugin benefits (install UX, discovery, governance) without imposing plugin-only constraints on users who prefer Homebrew or air-gapped installs.

## Target Users

- **Security engineers** managing vulnerability exceptions across scan and VEX workflows
- **Platform/DevOps teams** integrating Trivy into CI pipelines with VEX-based filtering
- **Compliance teams** needing machine-readable documentation of vulnerability assessment decisions

## Background: Formats

### .trivyignore.yaml

Trivy's structured ignore file. Authoritative field definition: [Trivy filtering documentation](https://trivy.dev/docs/latest/configuration/filtering/#trivyignoreyaml).

**Top-level sections:** `vulnerabilities`, `misconfigurations`, `secrets`, `licenses`. Only `vulnerabilities` entries are relevant for VEX conversion — the other three categories have no VEX status/justification counterparts and are silently ignored by this tool.

**Per-entry fields:**

| Field        | Required | Type              | Scope                       | Notes                                                                                                                                          |
|--------------|----------|-------------------|-----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| `id`         | Yes      | string            | all categories              | Identifier of the finding (CVE/GHSA for vulnerabilities).                                                                                       |
| `paths`      | No       | string array      | all categories              | File paths to scope the ignore. If unset, the ignore applies to all files. Does not function for OS-package licenses (apk/dpkg/rpm).            |
| `purls`      | No       | string array      | **vulnerabilities only**    | PURLs to scope the ignore to specific packages. If unset, the ignore applies to all packages (i.e. the suppression is *broader* without purls). |
| `expired_at` | No       | date (`yyyy-mm-dd`) | all categories            | Expiration date. If unset, the ignore is always valid.                                                                                          |
| `statement`  | No       | string            | all categories              | Human-readable reason. Not used by Trivy for filtering — purely documentary from Trivy's perspective; this tool uses it for pattern-based status inference. |

### OpenVEX

OpenVEX is a JSON-based standard for communicating vulnerability assessment decisions. Each document contains statements linking a vulnerability to a product with a status and justification.

VEX statuses:

| Status                | Meaning                                         | Required field       |
|-----------------------|-------------------------------------------------|----------------------|
| `not_affected`        | Product is not affected by the vulnerability    | `justification`      |
| `affected`            | Product is affected, risk acknowledged          | `action_statement`   |
| `fixed`               | Vulnerability has been fixed in this version    | —                    |
| `under_investigation` | Assessment is ongoing                           | —                    |

OpenVEX justifications (for `not_affected`):

- `component_not_present`
- `vulnerable_code_not_present`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `inline_mitigations_already_exist`

## Requirements

### Functional Requirements

#### FR-1: Conversion

| ID     | Requirement                                                                                                                       | Priority |
|--------|-----------------------------------------------------------------------------------------------------------------------------------|----------|
| FR-1.1 | Parse `.trivyignore.yaml` and extract `vulnerabilities` entries                                                                   | Must     |
| FR-1.2 | Generate a valid OpenVEX document from parsed entries                                                                             | Must     |
| FR-1.3 | Derive VEX status from the `statement` field using pattern-based inference (see Status Inference below)                           | Must     |
| FR-1.4 | Default to `affected` status with action statement "Risk accepted. {original statement}" when no pattern matches                  | Must     |
| FR-1.5 | Default to `affected` status with action statement "Risk accepted." when entry has no `statement`                                 | Must     |
| FR-1.6 | Skip entries with `expired_at` in the past (do not include in VEX output)                                                        | Must     |
| FR-1.7 | Include `expired_at` as a `Expires at: <yyyy-mm-dd>` section (value verbatim from the file) in the appropriate text field per status, when present and not expired. See "Output Specification" for the section-based composition. | Should   |
| FR-1.8 | Derive `vulnerability.@id` from the entry's ID prefix. Routing table: `CVE-*` → `https://nvd.nist.gov/vuln/detail/<id>`; `GHSA-*` → `https://github.com/advisories/<id>`; `GO-*` → `https://pkg.go.dev/vuln/<id>`; `RUSTSEC-*` → `https://rustsec.org/advisories/<id>`; `PYSEC-*` and `OSV-*` → `https://osv.dev/vulnerability/<id>`; unknown prefix → omit `@id` (spec-legal per OpenVEX v0.2 — only `vulnerability.name` is required). When a vulnerability report is available (FR-7.4), `PrimaryURL` overrides this routing. | Must     |

#### FR-2: Status Inference

| ID     | Requirement                                                                                                               | Priority |
|--------|---------------------------------------------------------------------------------------------------------------------------|----------|
| FR-2.1 | Map statements containing "not present", "not installed", "component not present" → `not_affected` / `component_not_present` | Must     |
| FR-2.2 | Map statements containing "not compiled in", "feature disabled", "excluded from build", "build flag off" → `not_affected` / `vulnerable_code_not_present` | Must     |
| FR-2.3 | Map statements containing "not reachable", "not in execute path", "dead code" → `not_affected` / `vulnerable_code_not_in_execute_path` | Must     |
| FR-2.4 | Map statements containing "cannot be controlled", "not exploitable" → `not_affected` / `vulnerable_code_cannot_be_controlled_by_adversary` | Must     |
| FR-2.5 | Map statements containing "mitigated", "mitigation", "compensating control" → `not_affected` / `inline_mitigations_already_exist` | Must     |
| FR-2.6 | Map statements containing "fixed", "patched", "upgraded", "resolved" → `fixed`                                            | Must     |
| FR-2.7 | Map statements containing "investigating", "under review", "evaluating" → `under_investigation`                            | Must     |
| FR-2.8 | Pattern matching is case-insensitive                                                                                       | Must     |
| FR-2.9 | When multiple patterns match, use the first matching rule in the order defined above                                       | Must     |

#### FR-3: Metadata & Identity

| ID     | Requirement                                                                                                               | Priority |
|--------|---------------------------------------------------------------------------------------------------------------------------|----------|
| FR-3.1 | Generate a document ID (`@id`) as an IRI. Default form: `urn:uuid:<random-uuid>`. Alternative Backstage-URL form derived when both `--backstage-url` and `catalog-info.yaml` are available (see FR-6.8). | Must     |
| FR-3.2 | Populate the document `author` field. Priority: `--author` override > derived from `catalog-info.yaml` per FR-6.5 (when read) > `"Unknown"` fallback (no catalog-info, no `--author`). | Must     |
| FR-3.3 | Populate the document `role` field only when a source is available. Priority: `--author-role` override > kind-derived default per FR-6.9 (when author is derived from `spec.owner`). Omitted entirely when the only signal for `author` is `--author` or the `"Unknown"` fallback. | Must     |

#### FR-4: Product Identification

| ID     | Requirement                                                                                                               | Priority |
|--------|---------------------------------------------------------------------------------------------------------------------------|----------|
| FR-4.1 | Accept product identifier via `--product` / `-p` CLI flag (e.g., container image reference or purl). Sole source of `products[].@id`. | Must     |
| FR-4.2 | When no product identifier is available, emit VEX statements without a `products` field (spec-legal per OpenVEX v0.2 — `products` is optional at statement level). | Must     |

#### FR-5: Subcomponent Mapping

| ID     | Requirement                                                                                                               | Priority |
|--------|---------------------------------------------------------------------------------------------------------------------------|----------|
| FR-5.1 | When an entry has a `purls:` field **and** `--product` is provided, emit each purl as an element of `products[0].subcomponents[]` with the shape `{"identifiers": {"purl": "<purl>"}}`. | Must     |
| FR-5.2 | When an entry has a `purls:` field but `--product` is **not** provided: (a) do not emit subcomponents (structurally impossible without a Product), (b) include an `Affected PURLs:` section (multi-line bullet list, `  - <purl>` per entry) in the appropriate text field for the statement's status (`impact_statement` for `not_affected`, `action_statement` for `affected`, `status_notes` for `fixed`/`under_investigation`), and (c) emit a stderr warning naming the count of affected entries and suggesting `--product`. See "Output Specification" for section composition. | Must     |

#### FR-6: Backstage Integration

| ID     | Requirement                                                                                                               | Priority |
|--------|---------------------------------------------------------------------------------------------------------------------------|----------|
| FR-6.1 | Read `catalog-info.yaml` from a path specified via `--catalog` flag (default: `catalog-info.yaml`)                        | Must     |
| FR-6.2 | Allow skipping catalog-info reading via `--no-catalog` flag                                                               | Must     |
| FR-6.3 | Fields consumed from `catalog-info.yaml`: top-level `kind`, `metadata.name`, `metadata.namespace` (default: `"default"` when absent), and `spec.owner`. Other fields are ignored. | Must     |
| FR-6.4 | Parse `spec.owner` as a Backstage entity reference. Default kind is `"group"`, default namespace is `"default"`. Non-Backstage-shaped values (e.g. IRIs like `mailto:*`) are treated as entity refs, not passed through verbatim — the user's escape hatch for IRI-shaped authors is `--author`. | Must     |
| FR-6.5 | Derive the `author` field from the resolved `spec.owner` entity ref. When `--backstage-url <u>` is provided, emit `<u>/catalog/<owner-namespace>/<owner-kind>/<owner-name>`. Otherwise emit the canonical entity ref form `<owner-kind>:<owner-namespace>/<owner-name>`. | Must     |
| FR-6.6 | Accept a Backstage instance host URL via `--backstage-url <u>` flag (host root, e.g. `https://backstage.example.com`, without `/catalog` suffix). | Must     |
| FR-6.7 | Accept an equivalent value via `TRIVYIGNORE_VEX_BACKSTAGE_URL` environment variable when `--backstage-url` is not provided. | Could    |
| FR-6.8 | When `--backstage-url` **and** `catalog-info.yaml` are both available, compose the document `@id` (per FR-3.1) as `<u>/catalog/<namespace>/<kind>/<name>#vex-<uuid>` using the entity's own kind/namespace/name. If either input is missing, fall back to `urn:uuid:<uuid>`. | Must     |
| FR-6.9 | When the `author` is derived from `spec.owner` (no `--author-role` override), default the `role` to `"<Kind> Owner"` using the top-level `kind` from `catalog-info.yaml` (e.g. `"Component Owner"`, `"System Owner"`, `"API Owner"`). Fall back to `"Owner"` if `kind` is missing or unresolvable. The `Kind` here is the *owned entity's* kind, not the owner's kind. | Must     |

#### FR-7: Vulnerability Report Enrichment

| ID     | Requirement                                                                                                               | Priority |
|--------|---------------------------------------------------------------------------------------------------------------------------|----------|
| FR-7.1 | Accept a Trivy scan JSON report via `--vuln-report <path>` flag. The report must be generated with `--show-suppressed` (so `Results[].ExperimentalModifiedFindings[]` is populated with the entries the `.trivyignore.yaml` suppressed). | Should   |
| FR-7.2 | Fields consumed from each `ExperimentalModifiedFindings[].Finding`: `VulnerabilityID` (index key), `PrimaryURL` (enriched `@id`), `VendorIDs[]` (populates `vulnerability.aliases[]`), `Description` (populates `vulnerability.description`). All other fields are ignored. | Must     |
| FR-7.3 | Build an index keyed by `Finding.VulnerabilityID` → `Finding`. For each `.trivyignore.yaml` vulnerability entry, look up its `id` in the index. | Must     |
| FR-7.4 | **Enrichment (matched entries):** `vulnerability.@id` ← `Finding.PrimaryURL` (falling back to the prefix-routed URL per FR-1.8 if `PrimaryURL` is empty). `vulnerability.aliases[]` ← `Finding.VendorIDs[]`. `vulnerability.description` ← `Finding.Description`. | Must     |
| FR-7.5 | **Relevance filter (unmatched entries):** Skip entries whose ID is not in the index. These entries represent suppressions for vulnerabilities Trivy did not detect in the current build (either the affected package is not installed or the installed version is outside the affected range). Not emitted in the VEX output. | Must     |
| FR-7.6 | Emit a stderr summary of filtered stale entries, listing each ID and suggesting removal from `.trivyignore.yaml`. Suppressible via `--quiet` / `-q` (see FR-8.5). | Should   |
| FR-7.7 | When `--vuln-report` is not provided, skip enrichment and filtering entirely — every `.trivyignore.yaml` entry becomes a VEX statement, and the `@id` URL is derived from prefix routing (FR-1.8) alone. | Must     |

#### FR-8: Input/Output

| ID     | Requirement                                                                                                               | Priority |
|--------|---------------------------------------------------------------------------------------------------------------------------|----------|
| FR-8.1 | Read `.trivyignore.yaml` from a path specified via `--input` / `-i` flag (default: `.trivyignore.yaml`)                   | Must     |
| FR-8.2 | Write OpenVEX JSON to stdout by default                                                                                   | Must     |
| FR-8.3 | Write OpenVEX JSON to a file via `--output` / `-o` flag                                                                   | Must     |
| FR-8.4 | Output must be valid OpenVEX that Trivy accepts via `--vex` flag                                                          | Must     |
| FR-8.5 | Suppress non-fatal stderr warnings via `--quiet` / `-q` flag. Errors that accompany a non-zero exit code are always emitted regardless of this flag. | Should   |

### Non-Functional Requirements

#### NFR-1: Compatibility

| ID      | Requirement                                                            | Priority |
|---------|------------------------------------------------------------------------|----------|
| NFR-1.1 | Work as a Trivy plugin (`plugin.yaml`)                                 | Must     |
| NFR-1.2 | Work standalone via direct execution                                   | Must     |
| NFR-1.3 | Support darwin/linux on amd64/arm64                                    | Must     |
| NFR-1.4 | Zero external runtime dependencies (single static binary)              | Must     |

#### NFR-2: Licensing & Compliance

| ID      | Requirement                                              | Priority |
|---------|----------------------------------------------------------|----------|
| NFR-2.1 | Apache-2.0 licensed, REUSE compliant                     | Must     |
| NFR-2.2 | REUSE compliance enforced via CI                         | Must     |

## CLI Interface

### Usage

As Trivy plugin:

```bash
trivy trivyignore-to-vex -i .trivyignore.yaml --product pkg:oci/my-image
```

Standalone:

```bash
trivyignore-to-vex -i .trivyignore.yaml --product pkg:oci/my-image -o .openvex.json
```

With Backstage catalog-info.yaml for author derivation and Backstage-URL document identity:

```bash
trivyignore-to-vex \
  -i .trivyignore.yaml \
  --product pkg:oci/my-image \
  --catalog catalog-info.yaml \
  --backstage-url https://backstage.example.com \
  -o .openvex.json
```

With a Trivy scan report as additional input for enrichment (`vulnerability.@id` → `PrimaryURL`, `aliases[]` → `VendorIDs[]`, `description` → `Description`) and relevance filtering (stale suppressions dropped from output):

```bash
# 1) Generate a Trivy scan report alongside your existing SBOM step.
#    --show-suppressed populates Results[].ExperimentalModifiedFindings[].
trivy image --format json --show-suppressed --output trivy.vulns.json my-image:tag

# 2) Feed the report into the converter alongside .trivyignore.yaml.
trivyignore-to-vex \
  -i .trivyignore.yaml \
  --catalog catalog-info.yaml \
  --backstage-url https://backstage.example.com \
  --product pkg:oci/my-image \
  --vuln-report trivy.vulns.json \
  -o .openvex.json
```

Attach VEX as an OCI referrer to a container image:

```bash
trivyignore-to-vex -i .trivyignore.yaml -p pkg:oci/my-image -o .openvex.json
oras attach --artifact-type application/vnd.openvex+json my-image:latest .openvex.json
```

Sign VEX as a cosign attestation on a container image:

```bash
trivyignore-to-vex -i .trivyignore.yaml -p pkg:oci/my-image -o .openvex.json
cosign attest --predicate .openvex.json --type openvex my-image:latest
```

Feed to another VEX-aware scanner:

```bash
trivyignore-to-vex -i .trivyignore.yaml -o .openvex.json
grype my-image:latest --vex .openvex.json
```

### Flags

| Flag                | Type   | Default                    | Description                                                                                                    |
|---------------------|--------|----------------------------|----------------------------------------------------------------------------------------------------------------|
| `--input`, `-i`     | string | `.trivyignore.yaml`        | Path to .trivyignore.yaml input file                                                                           |
| `--output`, `-o`    | string | *(stdout)*                 | Write OpenVEX JSON to file instead of stdout                                                                   |
| `--product`, `-p`   | string | *(omitted)*                | Product identifier (purl or image reference). Sole source of `products[].@id` per FR-4.1.                      |
| `--author`          | string | *(derived per FR-3.2)*     | VEX document author (overrides derivation from catalog-info.yaml)                                              |
| `--author-role`     | string | *(derived per FR-3.3)*     | VEX document author role (overrides derivation; sets role verbatim to the flag value)                          |
| `--catalog`         | string | `catalog-info.yaml`        | Path to Backstage catalog-info.yaml                                                                            |
| `--no-catalog`      | bool   | `false`                    | Skip reading catalog-info.yaml                                                                                 |
| `--backstage-url`   | string | *(from env var if set)*    | Backstage instance host URL (host root, no `/catalog` suffix). Enables Backstage-URL doc `@id` and author URL. |
| `--vuln-report`     | string | *(none)*                   | Path to Trivy scan JSON report (produced with `--show-suppressed`). Enables enrichment (`vulnerability.@id`, `aliases[]`, `description`) and relevance filtering (skip entries not in the current build). |
| `--quiet`, `-q`     | bool   | `false`                    | Suppress non-fatal stderr warnings. Errors accompanying non-zero exit codes are still emitted.                 |
| `--version`, `-v`   | bool   | `false`                    | Print version and exit                                                                                         |
| `--help`, `-h`      | bool   | `false`                    | Print help and exit                                                                                            |

Environment variables (COULD):

| Variable                            | Equivalent flag       | Notes                                                       |
|-------------------------------------|-----------------------|-------------------------------------------------------------|
| `TRIVYIGNORE_VEX_BACKSTAGE_URL`     | `--backstage-url`     | Used when the flag is not provided; flag takes precedence.  |

### Exit Codes

| Code | Meaning                                                    |
|------|------------------------------------------------------------|
| 0    | Success                                                    |
| 1    | Input file not found or not readable                       |
| 2    | Invalid input file (parse error)                           |

## Status Inference Rules

Pattern matching is applied in order. First match wins. All matching is case-insensitive.

| Priority | Keywords in `statement`                                                                        | VEX Status            | VEX Justification / Action                               |
|----------|------------------------------------------------------------------------------------------------|-----------------------|----------------------------------------------------------|
| 1        | "not present", "not installed", "component not present"                                        | `not_affected`        | `component_not_present`                                  |
| 2        | "not compiled in", "feature disabled", "excluded from build", "build flag off" | `not_affected`        | `vulnerable_code_not_present`                            |
| 3        | "not reachable", "not in execute path", "dead code"                                            | `not_affected`        | `vulnerable_code_not_in_execute_path`                    |
| 4        | "cannot be controlled", "not exploitable"                                                      | `not_affected`        | `vulnerable_code_cannot_be_controlled_by_adversary`      |
| 5        | "mitigated", "mitigation", "compensating control"                                              | `not_affected`        | `inline_mitigations_already_exist`                       |
| 6        | "fixed", "patched", "upgraded", "resolved"                                                     | `fixed`               | —                                                        |
| 7        | "investigating", "under review", "evaluating"                                                  | `under_investigation` | —                                                        |
| 8        | *(no match / default)*                                                                         | `affected`            | Action: "Risk accepted. {statement}"                     |

## Output Specification

### Section-based composition of text fields

The three OpenVEX statement text fields — `impact_statement`, `action_statement`, `status_notes` — are populated with a **section-based multi-line string** built from the entry's data. Each section is emitted only when its source data is present; empty sections are omitted along with their label. Sections are joined by a single `\n` (no blank lines between labels).

**Section list, in emission order:**

1. **`Risk accepted.`** — emitted only for `affected` status.
2. **`Expires at: <yyyy-mm-dd>`** — emitted when the entry has a non-expired `expired_at:` value; the date is verbatim from the file (ISO 8601 date-only). Per FR-1.7.
3. **`Affected PURLs:`** — emitted only when the entry has `purls:` **and** `--product` was not provided. Multi-line bullet list with `  - <purl>` per entry (two-space indent). Suppressed when `--product` is provided (purls go into structured `products[0].subcomponents[]` instead — see FR-5.1). Per FR-5.2.
4. **`Statement:\n<original statement>`** — emitted when the entry has a non-empty `statement:` field. The original prose is preserved verbatim.

**Target text field per status:**

| Status                    | Target field       |
|---------------------------|--------------------|
| `not_affected`            | `impact_statement` |
| `affected`                | `action_statement` |
| `fixed`                   | `status_notes`     |
| `under_investigation`     | `status_notes`     |

### Example — invocation with `--product`, `--catalog`, and `--backstage-url`

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://backstage.example.com/catalog/default/component/my-service#vex-<uuid>",
  "author": "https://backstage.example.com/catalog/default/group/security-team",
  "role": "Component Owner",
  "timestamp": "<ISO 8601 UTC>",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "@id": "https://nvd.nist.gov/vuln/detail/<CVE-ID>",
        "name": "<CVE-ID>"
      },
      "products": [
        {
          "@id": "pkg:oci/my-service@sha256:...",
          "subcomponents": [
            { "identifiers": { "purl": "pkg:npm/%40octokit/request" } }
          ]
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "Expires at: 2026-08-12\nStatement:\n<original statement>"
    },
    {
      "vulnerability": {
        "@id": "https://nvd.nist.gov/vuln/detail/<CVE-ID>",
        "name": "<CVE-ID>"
      },
      "products": [
        {
          "@id": "pkg:oci/my-service@sha256:..."
        }
      ],
      "status": "affected",
      "action_statement": "Risk accepted.\nExpires at: 2026-08-12\nStatement:\n<original statement>"
    }
  ]
}
```

Note that `Affected PURLs:` is absent in these statements — `--product` is set, so purls became structured subcomponents on the `not_affected` statement.

### Example — minimal invocation without `--product`, without catalog-info.yaml

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "urn:uuid:<random-uuid>",
  "author": "Unknown",
  "timestamp": "<ISO 8601 UTC>",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "@id": "https://nvd.nist.gov/vuln/detail/<CVE-ID>",
        "name": "<CVE-ID>"
      },
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "Expires at: 2026-08-12\nAffected PURLs:\n  - pkg:npm/%40octokit/request\nStatement:\n<original statement>"
    }
  ]
}
```

Here `Affected PURLs:` appears in the prose because `--product` is absent; a stderr warning is also emitted noting the fallback and suggesting `--product`.

### Example — invocation with `--vuln-report` (enriched)

When a Trivy scan report (`--show-suppressed`) is provided, matched entries are enriched with `PrimaryURL`, `VendorIDs[]` (cross-ID aliases), and `Description`:

```json
{
  "statements": [
    {
      "vulnerability": {
        "@id": "https://avd.aquasec.com/nvd/cve-2025-25290",
        "name": "CVE-2025-25290",
        "description": "@octokit/request sends parameterized requests to GitHub's APIs ... ReDoS ... Versions 9.2.1 and 8.4.1 fix the issue.",
        "aliases": ["GHSA-rmvr-2pp2-xj38"]
      },
      "products": [
        {
          "@id": "pkg:oci/my-service@sha256:...",
          "subcomponents": [
            { "identifiers": { "purl": "pkg:npm/%40octokit/request" } }
          ]
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "Expires at: 2026-08-12\nStatement:\n<original statement>"
    }
  ]
}
```

Entries whose ID doesn't appear in the report's `ExperimentalModifiedFindings[]` are **filtered from the output** and reported on stderr:

```
Note: 3 .trivyignore.yaml entries appear stale (no matching current-build finding):
  - GHSA-w5hq-g745-h8pq
  - CVE-2026-31808
  - CVE-2025-14505
Consider removing these from .trivyignore.yaml.
```

**Behavior notes:**

- `role` is emitted only when a source is available (see FR-3.3). Omitted entirely when the only signal for `author` is `--author` or the `"Unknown"` fallback.
- When no `--product` is provided, the `products` field is omitted from statements — this is spec-legal per OpenVEX v0.2 (`products` is optional at statement level).
- The `Risk accepted.` section is emitted only for `affected` status (whether or not the entry has an original `statement:`).
- When `statement:` is empty, the `Statement:` section is omitted entirely (no dangling label).
- Entries with `expired_at` in the past are excluded from the output.
- **`purls`** entries: mapped to `products[0].subcomponents[]` when `--product` is available (FR-5.1). When `--product` is absent, purls are emitted as the `Affected PURLs:` section in the appropriate text field and a stderr warning fires (FR-5.2).
- **`paths`** entries: parsed but not emitted in the VEX output. VEX has no file-path scoping concept, and paths don't identify what's shipped (typically OCI images or purls). If a specific use case requires paths in the output, it can be brought back as an explicit opt-in flag.
- **Vulnerability report enrichment** (FR-7): when `--vuln-report` is provided, entries matched against `ExperimentalModifiedFindings[]` get `vulnerability.@id` overridden by `Finding.PrimaryURL` (falling back to prefix routing per FR-1.8 when `PrimaryURL` is empty); `vulnerability.aliases[]` populated from `Finding.VendorIDs[]`; `vulnerability.description` populated from `Finding.Description`. Unmatched entries are filtered from output (stale suppressions — the affected package isn't in the current build) and listed on stderr for maintainer cleanup.

## Release Strategy

- **Build tool:** GoReleaser
- **Platforms:** darwin/amd64, darwin/arm64, linux/amd64, linux/arm64
- **Archives:** `trivyignore-to-vex_<version>_<os>-<arch>.tar.gz`
- **Trigger:** Git tag push (`v*`) via GitHub Actions
- **Distribution channels:**
  - GitHub Releases — canonical archives; source of truth for the direct-binary channel
  - Trivy plugin index — submit to [aquasecurity/trivy-plugin-index](https://github.com/aquasecurity/trivy-plugin-index) after the first stable release
  - Homebrew — publish formula to a `bonial-oss` tap (e.g. `bonial-oss/homebrew-tap`) via GoReleaser's Homebrew integration

## CI/CD

| Workflow         | Trigger           | Purpose                                   |
|------------------|-------------------|-------------------------------------------|
| Commitlint       | PRs to main       | Enforce conventional commit messages      |
| Tests            | Push to main, PRs | `go test ./... -v -race` + build          |
| REUSE Compliance | Push to main, PRs | Verify SPDX headers and REUSE.toml        |
| Release          | Tag push (`v*`)   | Cross-compile and publish GitHub Release  |

## Future Considerations (Out of Scope for v1)

- Direct Trivy DB read as an alternative to `--vuln-report` (FR-7). Would benefit pipelines that don't produce a Trivy scan JSON (`--vuln-report` requires a scan invocation with `--show-suppressed`). The DB is a bbolt file at `<cache-dir>/db/trivy.db` (schema v2 currently), placed by Trivy when a scan runs or when `trivy fs . --download-db-only` is executed. Trade-offs: adds a bbolt reader dependency and schema-version tracking, but covers `.trivyignore.yaml` IDs regardless of whether the current build surfaces them — useful when the pipeline doesn't include a per-invocation scan.
- Support for alternative VEX output formats. OpenVEX is the primary output because it works across every Trivy target (image, container, repo, sbom). **CycloneDX VEX** has narrower Trivy applicability — only usable with `trivy sbom` scans, and only in the "Independent BOM and VEX BOM" format (Trivy does not support the "Embedded VEX in BOM" variant). It is nonetheless a legitimate target for adopters whose workflow centers on SBOM scans rather than image scans, and for consumers of CycloneDX-native tooling outside Trivy (Dependency-Track and similar aggregators). **CSAF** is a more distant target, oriented toward vendor security advisories rather than internal suppression workflows.
- Config-file support for `--backstage-url` and other flags (currently CLI flag + env var only). A likely prerequisite for the custom-inference-rule work below, since inference rules are probably too complex to express via CLI arguments.
- Custom inference rule configuration (extend the pattern-based status inference with user-defined rules; likely depends on the config-file item above).
- VEX document versioning and update tracking. OpenVEX documents carry a monotonic `version` integer and (optionally) a `last_updated` timestamp. There is **no explicit "supersedes" pointer** in the spec — consumers infer version relationships by grouping documents on subject (product `@id` / purl) and picking the highest `version`. To produce meaningful versions rather than emitting `version: 1` on every generation, the tool would need to be **stateful**: know what `@id` and `version` it emitted previously for the same subject. Two secondary concerns follow: (a) *stable subject identity across runs* — versioning is meaningless if the caller changes `--product` between invocations; (b) *no-change detection* — re-running on an unchanged input shouldn't bump the version. Storage of the prior state is a downstream question (adjacent state file, remote lookup, or `--previous-vex <path>` flag). **When it earns priority:** delivery via a persistent VEX repository or aggregator, where the same subject accumulates multiple documents over time and consumers need to reconcile them. **When it stays low-priority:** delivery via OCI attestation (image-digest-based), where the digest itself carries the "which snapshot" identity and version numbers barely matter downstream.
