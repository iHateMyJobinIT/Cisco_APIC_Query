# Cisco_APIC_Query

Export tenant-level configuration from a production Cisco ACI APIC via REST API for lab import.

## What It Exports

| Object Class | Description |
|---|---|
| `fvTenant` | Tenants |
| `fvCtx` | VRFs |
| `fvBD` | Bridge Domains |
| `fvSubnet` | Subnets |
| `fvAp` | Application Profiles |
| `fvAEPg` | EPGs |
| `vzBrCP` / `vzSubj` | Contracts & Subjects |
| `vzFilter` / `vzEntry` | Filters & Entries |
| `l3extOut` / `l3extLNodeP` / `l3extLIfP` | L3Outs & Profiles |
| `fvRsBd` / `fvRsCtx` / `fvRsCons` / `fvRsProv` | Relationship Bindings |

The script produces two types of exports:

1. **`by_class/`** — One JSON file per MO class (flat, good for browsing)
2. **`by_tenant/`** — Full subtree per tenant (hierarchical, POST-able to a lab APIC)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the export
python apic_export.py
```

You will be prompted for your password. The script authenticates as `GWNSM\AQ9F` against `EDCAPIC01.Gwnsm.Guidewell.net`.

## Output Structure

```
exports/apic_export_<timestamp>/
  ├── by_class/
  │   ├── Tenants.json
  │   ├── VRFs.json
  │   ├── Bridge_Domains.json
  │   ├── EPGs.json
  │   └── ...
  ├── by_tenant/
  │   ├── <TenantA>.json
  │   ├── <TenantB>.json
  │   └── ...
  ├── all_classes_combined.json
  └── all_tenants_full.json
```

## Importing Into Lab

To recreate a tenant in your lab APIC, POST the per-tenant JSON:

```bash
curl -k -X POST \
  https://<lab-apic>/api/mo/uni.json \
  -H "Cookie: APIC-cookie=<token>" \
  -d @exports/apic_export_<ts>/by_tenant/<TenantName>.json
```

## Notes

- SSL verification is disabled (self-signed certs).
- Built-in tenants (`infra`, `common`, `mgmt`) are skipped during the full-tree export.
- The `rsp-prop-include=config-only` parameter excludes runtime/stats data so the export is clean for import.
