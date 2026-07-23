# trivyignore-to-vex

Trivy plugin that converts `.trivyignore.yaml` files into OpenVEX documents.

## Installation

```bash
trivy plugin install github.com/bonial-oss/trivy-plugin-trivyignore-to-vex
```

## Usage

```bash
trivy trivyignore-to-vex -i .trivyignore.yaml --product pkg:oci/my-image
```

Or standalone:

```bash
trivyignore-to-vex -i .trivyignore.yaml -o .openvex.json
```

Then use with Trivy scan:

```bash
trivy image --vex .openvex.json my-image:latest
```

## Flags

| Flag            | Default              | Description                                       |
|-----------------|----------------------|---------------------------------------------------|
| `-i`, `--input` | `.trivyignore.yaml`  | Path to .trivyignore.yaml                         |
| `-o`, `--output`| stdout               | Output file path                                  |
| `-p`, `--product`| *(derived)*         | Product identifier (purl or image ref)            |
| `--author`      | *(from catalog-info)*| VEX document author                               |
| `--catalog`     | `catalog-info.yaml`  | Path to catalog-info.yaml                         |
| `--no-catalog`  | `false`              | Skip catalog-info.yaml                            |
| `-v`, `--version`| ---                 | Print version                                     |

## Status Inference

Statements in `.trivyignore.yaml` are mapped to VEX statuses:

| Keywords                        | VEX Status            |
|---------------------------------|-----------------------|
| "not present", "not installed"  | `not_affected`        |
| "not reachable", "dead code"    | `not_affected`        |
| "mitigated", "compensating"     | `not_affected`        |
| "fixed", "patched", "upgraded"  | `fixed`               |
| "investigating", "under review" | `under_investigation` |
| *(default)*                     | `affected`            |
