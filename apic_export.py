#!/usr/bin/env python3
"""
Cisco ACI / APIC Tenant Configuration Exporter

Connects to a Cisco APIC via REST API and exports tenant-level
configuration objects (Tenants, VRFs, BDs, EPGs, Contracts, Filters,
L3Outs, App Profiles) as JSON files suitable for lab import.

Usage:
    python apic_export.py
"""

import json
import os
import sys
import getpass
import time
from datetime import datetime

import requests
import urllib3

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
APIC_HOST = "EDCAPIC01.Gwnsm.Guidewell.net"
APIC_BASE_URL = f"https://{APIC_HOST}"
AUTH_DOMAIN = "GWNSM"
USERNAME = "AQ9F"

# Tenant-level managed object classes to export individually
TENANT_MO_CLASSES = {
    "fvTenant":  "Tenants",
    "fvCtx":     "VRFs",
    "fvBD":      "Bridge_Domains",
    "fvSubnet":  "Subnets",
    "fvAp":      "App_Profiles",
    "fvAEPg":    "EPGs",
    "vzBrCP":    "Contracts",
    "vzSubj":    "Contract_Subjects",
    "vzFilter":  "Filters",
    "vzEntry":   "Filter_Entries",
    "l3extOut":  "L3Outs",
    "l3extLNodeP": "L3Out_Node_Profiles",
    "l3extLIfP": "L3Out_Interface_Profiles",
    "fvRsBd":    "EPG_to_BD_Bindings",
    "fvRsCtx":   "BD_to_VRF_Bindings",
    "fvRsCons":  "Contract_Consumer_Bindings",
    "fvRsProv":  "Contract_Provider_Bindings",
}

# Page size for queries (APIC default max is 100000)
PAGE_SIZE = 50000


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

    # -- auth ---------------------------------------------------------------
    def login(self, username: str, password: str, domain: str = "") -> None:
        """Authenticate and store the APIC token cookie."""
        login_url = f"{self.base_url}/api/aaaLogin.json"

        # Domain-qualified username: apic:<domain>\<user>
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
        # APIC sets the cookie automatically via the session, but we also
        # keep the token for explicit header use if needed.
        self.session.cookies.set("APIC-cookie", self.token)
        print("Authentication successful.\n")

    def logout(self) -> None:
        """Gracefully end the APIC session."""
        if self.token is None:
            return
        logout_url = f"{self.base_url}/api/aaaLogout.json"
        payload = {
            "aaaUser": {
                "attributes": {
                    "name": USERNAME,
                }
            }
        }
        try:
            self.session.post(logout_url, json=payload, timeout=10)
            print("\nLogged out of APIC.")
        except Exception:
            pass  # best-effort logout

    # -- queries ------------------------------------------------------------
    def get_class(self, mo_class: str, query_params: dict | None = None) -> list:
        """
        Query all objects of a given MO class, handling pagination.

        Returns the combined imdata list across all pages.
        """
        all_objects: list = []
        page = 0

        while True:
            params = dict(query_params or {})
            params["page"] = page
            params["page-size"] = PAGE_SIZE

            url = f"{self.base_url}/api/class/{mo_class}.json"
            resp = self.session.get(url, params=params, timeout=60)
            resp.raise_for_status()

            data = resp.json()
            total = int(data.get("totalCount", 0))
            imdata = data.get("imdata", [])
            all_objects.extend(imdata)

            # Check if we've retrieved everything
            if len(all_objects) >= total or len(imdata) == 0:
                break
            page += 1

        return all_objects

    def get_tenant_full_tree(self, tenant_dn: str) -> dict:
        """
        Fetch a single tenant with its full subtree (all children
        recursively). This is the best format for re-importing into
        a lab APIC.
        """
        url = f"{self.base_url}/api/mo/{tenant_dn}.json"
        params = {
            "rsp-subtree": "full",
            "rsp-prop-include": "config-only",  # skip runtime/stats
        }
        resp = self.session.get(url, params=params, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        if data.get("imdata"):
            return data["imdata"][0]
        return {}


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------
def save_json(data: object, filepath: str) -> None:
    """Write data to a JSON file with pretty formatting."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    print(f"  -> Saved {filepath}")


def export_class_objects(apic: APICSession, export_dir: str) -> dict:
    """
    Export each MO class to its own JSON file under export_dir/.
    Returns a dict of {class_name: object_list} for the combined export.
    """
    combined: dict = {}

    for mo_class, friendly_name in TENANT_MO_CLASSES.items():
        print(f"Fetching {friendly_name} ({mo_class}) ...")
        try:
            objects = apic.get_class(
                mo_class,
                query_params={"rsp-prop-include": "config-only"},
            )
            print(f"  Found {len(objects)} {friendly_name}")
            combined[mo_class] = objects

            # Individual class file
            save_json(
                {"totalCount": str(len(objects)), "imdata": objects},
                os.path.join(export_dir, "by_class", f"{friendly_name}.json"),
            )
        except requests.HTTPError as exc:
            print(f"  WARNING: Failed to fetch {mo_class}: {exc}")
            combined[mo_class] = []

    return combined


def export_tenant_trees(apic: APICSession, export_dir: str) -> list:
    """
    Export each tenant as a full subtree JSON — this is the format
    you POST back to a lab APIC to recreate the tenant.
    """
    print("Fetching tenant list for full-tree export ...")
    tenants = apic.get_class(
        "fvTenant",
        query_params={"rsp-prop-include": "config-only"},
    )

    tenant_trees: list = []
    for tenant_obj in tenants:
        dn = tenant_obj["fvTenant"]["attributes"]["dn"]
        name = tenant_obj["fvTenant"]["attributes"]["name"]

        # Skip the 3 built-in tenants — not useful for lab cloning
        if name in ("infra", "common", "mgmt"):
            print(f"  Skipping built-in tenant '{name}'")
            continue

        print(f"  Exporting tenant '{name}' full tree ...")
        tree = apic.get_tenant_full_tree(dn)
        if tree:
            tenant_trees.append(tree)
            save_json(
                {"totalCount": "1", "imdata": [tree]},
                os.path.join(export_dir, "by_tenant", f"{name}.json"),
            )

    return tenant_trees


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 64)
    print("  Cisco ACI / APIC — Tenant Configuration Exporter")
    print("=" * 64)
    print(f"  APIC:     {APIC_HOST}")
    print(f"  Domain:   {AUTH_DOMAIN}")
    print(f"  User:     {USERNAME}")
    print("=" * 64)
    print()

    password = getpass.getpass(f"Password for {AUTH_DOMAIN}\\{USERNAME}: ")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir = os.path.join("exports", f"apic_export_{timestamp}")

    apic = APICSession(APIC_BASE_URL, verify_ssl=False)

    try:
        apic.login(USERNAME, password, domain=AUTH_DOMAIN)

        # 1 ── Per-class flat exports (good for browsing / reference)
        print("-" * 64)
        print("Phase 1: Exporting individual object classes")
        print("-" * 64)
        combined = export_class_objects(apic, export_dir)

        # Save combined flat export
        save_json(combined, os.path.join(export_dir, "all_classes_combined.json"))

        # 2 ── Per-tenant full subtree exports (good for lab import)
        print()
        print("-" * 64)
        print("Phase 2: Exporting full tenant subtrees (for lab import)")
        print("-" * 64)
        tenant_trees = export_tenant_trees(apic, export_dir)

        # Save combined tenant tree export
        save_json(
            {"totalCount": str(len(tenant_trees)), "imdata": tenant_trees},
            os.path.join(export_dir, "all_tenants_full.json"),
        )

        # Summary
        print()
        print("=" * 64)
        print("  Export Complete")
        print("=" * 64)
        print(f"  Output directory: {export_dir}/")
        print(f"  Tenant trees:     {len(tenant_trees)}")
        total_objs = sum(len(v) for v in combined.values())
        print(f"  Total objects:    {total_objs}")
        print()
        print("  To import a tenant into your lab APIC, POST the tenant")
        print("  JSON file to: https://<lab-apic>/api/mo/uni.json")
        print("=" * 64)

    except requests.HTTPError as exc:
        print(f"\nERROR: APIC request failed: {exc}", file=sys.stderr)
        if exc.response is not None:
            print(exc.response.text, file=sys.stderr)
        sys.exit(1)
    except requests.ConnectionError:
        print(
            f"\nERROR: Could not connect to {APIC_HOST}. "
            "Check hostname, network, and VPN.",
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
