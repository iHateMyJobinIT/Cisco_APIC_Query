#!/usr/bin/env python3
"""
Cisco ACI / APIC Lab Tenant Importer

Connects to a lab APIC, imports fabric-level policies (AEPs, domains,
VLAN pools), deletes all non-built-in tenants, then imports sanitized
tenant configurations exported by apic_export.py.

The sanitizer strips hardware-specific bindings (static paths, node
associations, interface paths) so configs from a large production fabric
import cleanly into a small lab with virtual leafs/spines.

Usage:
    python apic_lab_import.py [export_dir]

    export_dir  Path to an export directory (e.g. exports/apic_export_20260219_095402).
                If omitted, the script picks the most recent export in exports/.
"""

import json
import os
import sys
import glob
import getpass
import time
import copy

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Lab APIC Configuration
# ---------------------------------------------------------------------------
LAB_APIC_HOST = "10.20.20.220"
LAB_APIC_BASE_URL = f"https://{LAB_APIC_HOST}"
LAB_USERNAME = "admin"

# Built-in tenants that must NEVER be deleted
PROTECTED_TENANTS = {"infra", "common", "mgmt"}

# ---------------------------------------------------------------------------
# Hardware-specific MO classes to STRIP from tenant subtrees.
#
# These reference production leaf/spine node IDs, physical ports, and
# interface paths that don't exist in the lab. Removing them lets the
# logical policy structure (tenants/VRFs/BDs/EPGs/contracts) import
# cleanly without errors.
# ---------------------------------------------------------------------------
STRIP_MO_CLASSES = {
    # EPG static bindings → specific leaf/port/vPC paths
    "fvRsPathAtt",
    # EPG static node bindings → specific leaf node IDs
    "fvRsNodeAtt",
    # L3Out node-level associations → specific node IDs (e.g. node-201)
    "l3extRsNodeL3OutAtt",
    # L3Out interface path attachments → specific physical interfaces
    "l3extRsPathL3OutAtt",
    # Static endpoint entries
    "fvStCEp",
    "fvStIp",
    # Fabric path endpoint references
    "fvNodeConnEp",
    # L3Out member interfaces (SVI/routed sub-interface paths)
    "l3extMember",
    # Deprecated in ACI 6.1(2f) — endpoint-to-endpoint debug/traceability
    "dbgacEpToEp",
}

# MO classes to strip from fabric policy objects (AEPs).
# infraProvAcc / infraRsFuncToEpg bind AEPs to the infra tenant's EPGs
# with VLAN encaps that conflict with the lab's own infra VLAN setup.
STRIP_FABRIC_MO_CLASSES = {
    "infraProvAcc",
    "infraRsFuncToEpg",
}

# Attributes to scrub from specific MO classes.
# OSPF interface profiles exported from prod may have authType set to
# "md5" or "simple" with an empty authKey. Newer APIC firmware rejects
# that combo. We scrub ALL three auth attrs so authType falls back to
# its default ("none") and no key is required.
SCRUB_ATTRIBUTES = {
    "ospfIfP":  {"authKey", "authKeyId", "authType"},
    "ospfIfPol": {"authKey", "authKeyId", "authType"},
}


# ---------------------------------------------------------------------------
# APIC Session
# ---------------------------------------------------------------------------
class APICSession:
    """Manages authentication and REST calls to Cisco APIC."""

    def __init__(self, base_url: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.token = None

    def login(self, username: str, password: str, domain: str = "") -> None:
        login_url = f"{self.base_url}/api/aaaLogin.json"
        if domain:
            login_name = f"apic:{domain}\\{username}"
        else:
            login_name = username

        payload = {
            "aaaUser": {
                "attributes": {
                    "name": login_name,
                    "pwd": password,
                }
            }
        }

        print(f"Authenticating as '{login_name}' against {self.base_url} ...")
        resp = self.session.post(login_url, json=payload, timeout=30)
        resp.raise_for_status()

        data = resp.json()
        self.token = data["imdata"][0]["aaaLogin"]["attributes"]["token"]
        self.session.cookies.set("APIC-cookie", self.token)
        print("Authentication successful.\n")

    def logout(self) -> None:
        if self.token is None:
            return
        try:
            self.session.post(
                f"{self.base_url}/api/aaaLogout.json",
                json={"aaaUser": {"attributes": {"name": LAB_USERNAME}}},
                timeout=10,
            )
            print("\nLogged out of lab APIC.")
        except Exception:
            pass

    def get_class(self, mo_class: str, query_params: dict | None = None) -> list:
        all_objects: list = []
        page = 0
        while True:
            params = dict(query_params or {})
            params["page"] = page
            params["page-size"] = 50000
            url = f"{self.base_url}/api/class/{mo_class}.json"
            resp = self.session.get(url, params=params, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            total = int(data.get("totalCount", 0))
            imdata = data.get("imdata", [])
            all_objects.extend(imdata)
            if len(all_objects) >= total or len(imdata) == 0:
                break
            page += 1
        return all_objects

    def delete_mo(self, dn: str) -> requests.Response:
        url = f"{self.base_url}/api/mo/{dn}.json"
        resp = self.session.delete(url, timeout=30)
        resp.raise_for_status()
        return resp

    def post_mo(self, dn: str, payload: dict) -> requests.Response:
        url = f"{self.base_url}/api/mo/{dn}.json"
        resp = self.session.post(url, json=payload, timeout=120)
        resp.raise_for_status()
        return resp


# ---------------------------------------------------------------------------
# Sanitizer — strip hardware-specific bindings from tenant subtrees
# ---------------------------------------------------------------------------
def sanitize_tree(node: dict, strip_classes: set | None = None) -> dict:
    """
    Recursively walk an ACI MO tree and:
      1. Remove children whose class is in strip_classes
      2. Scrub problematic attributes (OSPF auth keys, etc.)

    Returns a deep-copied, cleaned tree.

    ACI JSON structure:
        { "fvAEPg": { "attributes": {...}, "children": [ ... ] } }

    Each child in the children list is itself a dict with a single key
    (the MO class name).
    """
    if strip_classes is None:
        strip_classes = STRIP_MO_CLASSES

    cleaned = {}

    for mo_class, mo_body in node.items():
        new_body = {}

        # Copy attributes, scrubbing problematic ones
        if "attributes" in mo_body:
            attrs = copy.deepcopy(mo_body["attributes"])
            if mo_class in SCRUB_ATTRIBUTES:
                for attr_name in SCRUB_ATTRIBUTES[mo_class]:
                    attrs.pop(attr_name, None)
            new_body["attributes"] = attrs

        # Recursively process children, stripping blacklisted classes
        if "children" in mo_body:
            new_children = []
            for child in mo_body["children"]:
                child_class = next(iter(child))
                if child_class in strip_classes:
                    continue  # strip this child
                sanitized_child = sanitize_tree(child, strip_classes)
                new_children.append(sanitized_child)

            if new_children:
                new_body["children"] = new_children

        cleaned[mo_class] = new_body

    return cleaned


def count_stripped(original: dict, sanitized: dict) -> int:
    """Count how many MO nodes were removed by sanitization."""
    def count_nodes(tree: dict) -> int:
        total = 0
        for mo_class, mo_body in tree.items():
            total += 1
            for child in mo_body.get("children", []):
                total += count_nodes(child)
        return total

    return count_nodes(original) - count_nodes(sanitized)


# ---------------------------------------------------------------------------
# Import fabric-level policies (AEPs, domains, VLAN pools)
# ---------------------------------------------------------------------------
# Mapping of MO class → parent DN for POSTing
FABRIC_POLICY_PARENTS = {
    "fvnsVlanInstP":   "uni/infra",
    "physDomP":        "uni",
    "l3extDomP":       "uni",
    "vmmDomP":         "uni",
    "infraAttEntityP": "uni/infra",
}

# Import order matters: VLAN pools first, then domains, then AEPs
FABRIC_IMPORT_ORDER = [
    ("fvnsVlanInstP",   "VLAN_Pools",        "VLAN Pools"),
    ("physDomP",        "Physical_Domains",   "Physical Domains"),
    ("l3extDomP",       "L3_Domains",         "L3 Domains"),
    ("vmmDomP",         "VMM_Domains",        "VMM Domains"),
    ("infraAttEntityP", "AEPs",              "AEPs"),
]


def import_fabric_policies(apic: APICSession, export_dir: str) -> tuple[int, int]:
    """
    Import fabric-level policies from the fabric_policies/ subdirectory.
    Returns (success_count, fail_count).
    """
    fabric_dir = os.path.join(export_dir, "fabric_policies")

    if not os.path.isdir(fabric_dir):
        print("  No fabric_policies/ directory found — skipping.")
        print("  (Re-run apic_export.py to include fabric policies.)")
        return 0, 0

    success = 0
    fail = 0

    for mo_class, filename, friendly_name in FABRIC_IMPORT_ORDER:
        filepath = os.path.join(fabric_dir, f"{filename}.json")
        if not os.path.isfile(filepath):
            print(f"  No {filename}.json found — skipping {friendly_name}")
            continue

        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        objects = data.get("imdata", [])
        if not objects:
            print(f"  {friendly_name}: 0 objects — skipping")
            continue

        parent_dn = FABRIC_POLICY_PARENTS[mo_class]
        print(f"  Importing {len(objects)} {friendly_name} ...")

        for obj in objects:
            # Sanitize AEPs — strip infra EPG bindings that conflict
            # with the lab's own infra VLAN assignments
            if mo_class == "infraAttEntityP":
                obj = sanitize_tree(obj, strip_classes=STRIP_FABRIC_MO_CLASSES)

            attrs = obj[mo_class]["attributes"]
            name = attrs.get("name", attrs.get("dn", "?"))
            try:
                apic.post_mo(parent_dn, obj)
                print(f"    {name} ... OK")
                success += 1
            except requests.HTTPError as exc:
                error_detail = ""
                if exc.response is not None:
                    try:
                        err = exc.response.json()
                        errors = err.get("imdata", [])
                        if errors:
                            error_detail = errors[0].get("error", {}).get(
                                "attributes", {}
                            ).get("text", "")
                    except Exception:
                        pass
                print(f"    {name} ... FAILED - {exc}")
                if error_detail:
                    print(f"      Detail: {error_detail}")
                fail += 1

    return success, fail


# ---------------------------------------------------------------------------
# Delete existing lab tenants
# ---------------------------------------------------------------------------
def delete_lab_tenants(apic: APICSession) -> list[str]:
    """Delete all tenants on the lab APIC except protected ones."""
    print("Fetching current lab tenants ...")
    tenants = apic.get_class("fvTenant")

    deleted = []
    for t in tenants:
        name = t["fvTenant"]["attributes"]["name"]
        dn = t["fvTenant"]["attributes"]["dn"]

        if name in PROTECTED_TENANTS:
            print(f"  SKIP (protected): {name}")
            continue

        print(f"  Deleting tenant: {name} ...", end=" ")
        try:
            apic.delete_mo(dn)
            print("OK")
            deleted.append(name)
        except requests.HTTPError as exc:
            print(f"FAILED - {exc}")

    if deleted:
        print(f"\n  Deleted {len(deleted)} tenant(s). Waiting 5s for fabric to converge ...")
        time.sleep(5)
    else:
        print("  No tenants to delete.")

    return deleted


# ---------------------------------------------------------------------------
# Import tenant trees (sanitized)
# ---------------------------------------------------------------------------
def import_tenant_trees(apic: APICSession, export_dir: str) -> tuple[list, list]:
    """
    Import tenant JSON files from by_tenant/, stripping hardware-specific
    bindings so they're compatible with the lab topology.
    Returns (succeeded, failed) lists of tenant names.
    """
    tenant_dir = os.path.join(export_dir, "by_tenant")

    if not os.path.isdir(tenant_dir):
        print(f"ERROR: No by_tenant/ directory found in {export_dir}")
        sys.exit(1)

    tenant_files = sorted(glob.glob(os.path.join(tenant_dir, "*.json")))

    if not tenant_files:
        print(f"ERROR: No tenant JSON files found in {tenant_dir}")
        sys.exit(1)

    print(f"Found {len(tenant_files)} tenant file(s) to import:\n")

    succeeded = []
    failed = []

    for filepath in tenant_files:
        tenant_name = os.path.splitext(os.path.basename(filepath))[0]

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            if "imdata" in data and data["imdata"]:
                original = data["imdata"][0]
            else:
                original = data

            # Sanitize: strip hardware-specific bindings
            sanitized = sanitize_tree(original)
            stripped = count_stripped(original, sanitized)

            print(f"  Importing tenant: {tenant_name} "
                  f"(stripped {stripped} hardware-specific nodes) ...",
                  end=" ", flush=True)

            apic.post_mo("uni", sanitized)
            print("OK")
            succeeded.append(tenant_name)

            time.sleep(2)

        except requests.HTTPError as exc:
            error_detail = ""
            if exc.response is not None:
                try:
                    err_body = exc.response.json()
                    errors = err_body.get("imdata", [])
                    if errors:
                        error_detail = errors[0].get("error", {}).get(
                            "attributes", {}
                        ).get("text", "")
                except Exception:
                    error_detail = exc.response.text[:200]
            print(f"FAILED - {exc}")
            if error_detail:
                print(f"         Detail: {error_detail}")
            failed.append(tenant_name)

        except (json.JSONDecodeError, KeyError) as exc:
            print(f"FAILED - Bad JSON: {exc}")
            failed.append(tenant_name)

    return succeeded, failed


# ---------------------------------------------------------------------------
# Find the most recent export directory
# ---------------------------------------------------------------------------
def find_latest_export() -> str | None:
    """Return the most recently created export directory."""
    export_base = "exports"
    if not os.path.isdir(export_base):
        return None
    dirs = sorted(glob.glob(os.path.join(export_base, "apic_export_*")))
    return dirs[-1] if dirs else None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 64)
    print("  Cisco ACI / APIC — Lab Tenant Importer")
    print("=" * 64)
    print(f"  Lab APIC:  {LAB_APIC_HOST}")
    print(f"  User:      {LAB_USERNAME}")
    print(f"  Protected: {', '.join(sorted(PROTECTED_TENANTS))}")
    print("=" * 64)
    print()

    # Determine export directory
    if len(sys.argv) > 1:
        export_dir = sys.argv[1]
    else:
        export_dir = find_latest_export()
        if export_dir is None:
            print("ERROR: No export directory found. Run apic_export.py first,")
            print("       or pass the export path as an argument:")
            print("       python apic_lab_import.py exports/apic_export_20260219_095402")
            sys.exit(1)

    if not os.path.isdir(export_dir):
        print(f"ERROR: Directory not found: {export_dir}")
        sys.exit(1)

    print(f"Export source: {export_dir}")
    print()

    # List what will be imported
    tenant_dir = os.path.join(export_dir, "by_tenant")
    if os.path.isdir(tenant_dir):
        tenant_files = sorted(glob.glob(os.path.join(tenant_dir, "*.json")))
        tenant_names = [os.path.splitext(os.path.basename(f))[0] for f in tenant_files]
        print(f"Tenants to import: {', '.join(tenant_names)}")

    fabric_dir = os.path.join(export_dir, "fabric_policies")
    has_fabric = os.path.isdir(fabric_dir)
    if has_fabric:
        print("Fabric policies:   AEPs, Domains, VLAN Pools")

    print()
    print("The following hardware-specific objects will be STRIPPED")
    print("from tenant configs for lab compatibility:")
    for mo_class in sorted(STRIP_MO_CLASSES):
        print(f"  - {mo_class}")
    print()

    # Confirmation prompt
    print("WARNING: This will DELETE all non-protected tenants on the lab")
    print(f"         APIC ({LAB_APIC_HOST}) before importing production configs.")
    print()
    confirm = input("Type 'yes' to proceed: ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        sys.exit(0)

    print()
    password = getpass.getpass(f"Password for {LAB_USERNAME}@{LAB_APIC_HOST}: ")

    apic = APICSession(LAB_APIC_BASE_URL, verify_ssl=False)

    try:
        apic.login(LAB_USERNAME, password)

        # Phase 1: Import fabric policies (AEPs, domains, VLAN pools)
        if has_fabric:
            print("-" * 64)
            print("Phase 1: Importing fabric policies (AEPs, domains, VLAN pools)")
            print("-" * 64)
            fab_ok, fab_fail = import_fabric_policies(apic, export_dir)
            print(f"\n  Fabric policies: {fab_ok} succeeded, {fab_fail} failed")
            if fab_ok > 0:
                print("  Waiting 5s for fabric to converge ...")
                time.sleep(5)
        else:
            print("-" * 64)
            print("Phase 1: No fabric policies to import (re-export to include them)")
            print("-" * 64)
            fab_ok, fab_fail = 0, 0

        # Phase 2: Delete existing lab tenants
        print()
        print("-" * 64)
        print("Phase 2: Cleaning lab — deleting non-protected tenants")
        print("-" * 64)
        deleted = delete_lab_tenants(apic)

        # Phase 3: Import sanitized production tenant trees
        print()
        print("-" * 64)
        print("Phase 3: Importing production tenants (sanitized for lab)")
        print("-" * 64)
        succeeded, failed = import_tenant_trees(apic, export_dir)

        # Summary
        print()
        print("=" * 64)
        print("  Import Complete")
        print("=" * 64)
        print(f"  Fabric policies imported: {fab_ok} ({fab_fail} failed)")
        print(f"  Tenants deleted from lab: {len(deleted)}")
        print(f"  Tenants imported:         {len(succeeded)}")
        if succeeded:
            print(f"    Succeeded: {', '.join(succeeded)}")
        if failed:
            print(f"    FAILED:    {', '.join(failed)}")
        print()
        if failed:
            print("  Some tenants failed. Check error details above.")
            print("  Common causes:")
            print("    - Missing VMM domain on lab (if EPGs reference vCenter)")
            print("    - Missing L3 domain (if L3Outs reference one)")
            print("    - Re-run export with latest apic_export.py to capture")
            print("      fabric policies, then re-import.")
        else:
            print("  All tenants imported successfully!")
            print("  Hardware-specific bindings were stripped — your lab now")
            print("  has the full logical policy structure from production.")
        print("=" * 64)

    except requests.HTTPError as exc:
        print(f"\nERROR: APIC request failed: {exc}", file=sys.stderr)
        if exc.response is not None:
            print(exc.response.text, file=sys.stderr)
        sys.exit(1)
    except requests.ConnectionError:
        print(
            f"\nERROR: Could not connect to {LAB_APIC_HOST}. "
            "Check IP, network, and VPN.",
            file=sys.stderr,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(130)
    finally:
        apic.logout()


if __name__ == "__main__":
    main()
