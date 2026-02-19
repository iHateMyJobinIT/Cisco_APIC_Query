#!/usr/bin/env python3
"""
Cisco ACI / APIC Lab Tenant Importer

Connects to a lab APIC, deletes all non-built-in tenants, then imports
tenant configurations exported by apic_export.py.

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
# APIC Session (reused from export script)
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
        # Give the fabric a moment to converge after deletions
        print(f"\n  Deleted {len(deleted)} tenant(s). Waiting 5s for fabric to converge ...")
        time.sleep(5)
    else:
        print("  No tenants to delete.")

    return deleted


# ---------------------------------------------------------------------------
# Import tenant trees
# ---------------------------------------------------------------------------
def import_tenant_trees(apic: APICSession, export_dir: str) -> tuple[list, list]:
    """
    Import tenant JSON files from the by_tenant/ subdirectory.
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
        print(f"  Importing tenant: {tenant_name} ...", end=" ", flush=True)

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # The file format is {"totalCount": "1", "imdata": [<tenant_tree>]}
            if "imdata" in data and data["imdata"]:
                payload = data["imdata"][0]
            else:
                payload = data

            # POST to uni (the root of the MIT)
            apic.post_mo("uni", payload)
            print("OK")
            succeeded.append(tenant_name)

            # Brief pause between tenants to let the fabric process
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

        # Phase 1: Delete existing lab tenants
        print("-" * 64)
        print("Phase 1: Cleaning lab — deleting non-protected tenants")
        print("-" * 64)
        deleted = delete_lab_tenants(apic)

        # Phase 2: Import production tenant trees
        print()
        print("-" * 64)
        print("Phase 2: Importing production tenant configs")
        print("-" * 64)
        succeeded, failed = import_tenant_trees(apic, export_dir)

        # Summary
        print()
        print("=" * 64)
        print("  Import Complete")
        print("=" * 64)
        print(f"  Tenants deleted from lab:  {len(deleted)}")
        print(f"  Tenants imported:          {len(succeeded)}")
        if succeeded:
            print(f"    Succeeded: {', '.join(succeeded)}")
        if failed:
            print(f"    FAILED:    {', '.join(failed)}")
        print()
        if failed:
            print("  Some tenants failed to import. This can happen if the lab")
            print("  APIC is missing fabric-level policies (interface profiles,")
            print("  VMM domains, etc.) that the tenants reference. Check the")
            print("  errors above and create the missing objects on the lab first.")
        else:
            print("  All tenants imported successfully!")
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
