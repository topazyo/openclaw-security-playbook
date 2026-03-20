"""Access review backend for openclaw-cli scan access.

Implements the analysis rules from docs/procedures/access-review.md:

  - Inactive user detection  (no login within the ``--days`` threshold)
  - Privilege-creep detection (Admin+Developer combo, or prod access in non-prod role)
  - Orphaned-approver detection (GrantedBy user absent from the current user list)

Input sources
-------------
csv
    Path to a CSV exported from your IdP following the runbook column set:
    UserID, Name, Email, Role, Systems, LastLogin, GrantedDate, GrantedBy

azure-ad
    Live query via Microsoft Graph.  Requires the calling app to hold the
    ``User.Read.All`` and ``AuditLog.Read.All`` delegated scopes.
    Credentials are read from explicit keyword args or from environment
    variables: AZURE_AD_TENANT_ID, AZURE_AD_CLIENT_ID, AZURE_AD_CLIENT_SECRET.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# CSV ingestion
# ---------------------------------------------------------------------------

REQUIRED_COLUMNS = frozenset({
    "UserID", "Name", "Email", "Role", "Systems",
    "LastLogin", "GrantedDate", "GrantedBy",
})

_DATE_FMTS = ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
              "%m/%d/%Y", "%d/%m/%Y")


def _parse_date(raw: str) -> datetime | None:
    raw = raw.strip()
    if not raw:
        return None
    for fmt in _DATE_FMTS:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def load_csv(path: str) -> list[dict[str, str]]:
    """Load an access-report CSV and return a list of row dicts.

    The CSV must contain all columns listed in ``REQUIRED_COLUMNS`` (the
    runbook export format from docs/procedures/access-review.md § Phase 1).
    """
    p = Path(path).expanduser().resolve()
    text = p.read_text(encoding="utf-8-sig")   # strip BOM if present
    reader = csv.DictReader(StringIO(text))
    rows = list(reader)
    if not rows:
        return []
    missing = REQUIRED_COLUMNS - set(rows[0].keys())
    if missing:
        raise ValueError(
            f"CSV is missing required columns: {sorted(missing)}. "
            f"Expected: {sorted(REQUIRED_COLUMNS)}"
        )
    return rows


# ---------------------------------------------------------------------------
# Azure AD / Microsoft Graph adapter
# ---------------------------------------------------------------------------

def _graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain an app-only bearer token from Microsoft identity platform."""
    try:
        import requests  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "Install 'requests' to use the Azure AD provider: pip install requests"
        ) from exc

    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    resp = requests.post(
        url,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _graph_get(endpoint: str, token: str) -> dict[str, Any]:
    try:
        import requests  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "Install 'requests' to use the Azure AD provider: pip install requests"
        ) from exc

    resp = requests.get(
        endpoint,
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def load_azure_ad(
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> list[dict[str, str]]:
    """Fetch users from Azure AD via Microsoft Graph and normalise to the
    same row schema used by ``load_csv()``.

    signInActivity (last sign-in date) requires an Azure AD Premium P1/P2
    licence on the tenant.  If the field is absent, ``LastLogin`` will be
    empty and the user will be flagged for review.
    """
    tenant_id = tenant_id or os.environ.get("AZURE_AD_TENANT_ID", "")
    client_id = client_id or os.environ.get("AZURE_AD_CLIENT_ID", "")
    client_secret = client_secret or os.environ.get("AZURE_AD_CLIENT_SECRET", "")

    if not all([tenant_id, client_id, client_secret]):
        raise ValueError(
            "Azure AD provider requires AZURE_AD_TENANT_ID, AZURE_AD_CLIENT_ID, "
            "and AZURE_AD_CLIENT_SECRET environment variables (or explicit args)."
        )

    token = _graph_token(tenant_id, client_id, client_secret)

    endpoint: str | None = (
        "https://graph.microsoft.com/v1.0/users"
        "?$select=id,displayName,userPrincipalName,jobTitle,signInActivity,createdDateTime"
        "&$top=999"
    )
    rows: list[dict[str, str]] = []
    while endpoint:
        page = _graph_get(endpoint, token)
        for u in page.get("value", []):
            sa = u.get("signInActivity") or {}
            last_login = (
                sa.get("lastSignInDateTime")
                or sa.get("lastNonInteractiveSignInDateTime")
                or ""
            )
            rows.append({
                "UserID": u.get("id", ""),
                "Name": u.get("displayName", ""),
                "Email": u.get("userPrincipalName", ""),
                "Role": u.get("jobTitle", ""),
                "Systems": "",          # not directly available in basic Graph query
                "LastLogin": last_login,
                "GrantedDate": u.get("createdDateTime", ""),
                "GrantedBy": "",        # not available in basic Graph query
                "_source": "azure_ad",
            })
        endpoint = page.get("@odata.nextLink")  # handle pagination

    return rows


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

def analyze_access(
    rows: list[dict[str, str]],
    *,
    days_threshold: int = 90,
) -> dict[str, list[dict[str, Any]]]:
    """Apply the access-review rules and return a findings dict.

    The three finding categories match the runbook phases:
      - inactive_users
      - privilege_creep
      - orphaned_approvers
    """
    now = datetime.now(UTC)
    all_user_ids = {r.get("UserID", "").strip() for r in rows if r.get("UserID")}

    inactive_users: list[dict[str, Any]] = []
    privilege_creep: list[dict[str, Any]] = []
    orphaned_approvers: list[dict[str, Any]] = []

    already_flagged_creep: set[str] = set()

    for row in rows:
        user_id = row.get("UserID", "").strip()
        email = row.get("Email", "").strip()
        role_raw = row.get("Role", "").strip()
        systems = [s.strip() for s in row.get("Systems", "").split(",") if s.strip()]
        granted_by = row.get("GrantedBy", "").strip()
        last_login_raw = row.get("LastLogin", "").strip()

        # --- Inactive-user rule ---
        last_login_dt = _parse_date(last_login_raw)
        if last_login_dt is None:
            inactive_users.append({
                "user_id": user_id,
                "email": email,
                "role": role_raw,
                "last_login": "",
                "days_inactive": None,
                "recommendation": "no login date recorded; review immediately",
            })
        else:
            days = (now - last_login_dt).days
            if days >= days_threshold:
                inactive_users.append({
                    "user_id": user_id,
                    "email": email,
                    "role": role_raw,
                    "last_login": last_login_raw,
                    "days_inactive": days,
                    "recommendation": "review and revoke if no longer needed",
                })

        # --- Privilege-creep rules ---
        roles = {r.strip().lower() for r in role_raw.split(",") if r.strip()}

        if "admin" in roles and "developer" in roles:
            privilege_creep.append({
                "user_id": user_id,
                "email": email,
                "roles": sorted(roles),
                "issue": "holds both Admin and Developer roles simultaneously",
            })
            already_flagged_creep.add(user_id)

        prod_access = any(s.lower() in ("prod", "production") for s in systems)
        non_prod_roles = {"developer", "operator", "viewer", "read-only", "developer"}
        if prod_access and roles and roles.issubset(non_prod_roles) and user_id not in already_flagged_creep:
            privilege_creep.append({
                "user_id": user_id,
                "email": email,
                "roles": sorted(roles),
                "systems": systems,
                "issue": "production system access granted to non-production role",
            })
            already_flagged_creep.add(user_id)

        # --- Orphaned-approver rule ---
        if granted_by and granted_by not in all_user_ids:
            orphaned_approvers.append({
                "user_id": user_id,
                "email": email,
                "granted_by": granted_by,
                "issue": "access approver (GrantedBy) not found in current user list",
            })

    return {
        "inactive_users": inactive_users,
        "privilege_creep": privilege_creep,
        "orphaned_approvers": orphaned_approvers,
    }


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _write_findings_csv(
    path: str,
    rows: list[dict[str, Any]],
    fields: list[str],
) -> None:
    out = Path(path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_access_review(
    *,
    input_csv: str | None = None,
    provider: str | None = None,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    days_threshold: int = 90,
    output_path: str | None = None,
    output_inactive_csv: str | None = None,
    output_privilege_creep_csv: str | None = None,
) -> dict[str, Any]:
    """Run an access review and return the canonical result dict.

    Exactly one of ``input_csv`` or ``provider`` must be supplied.

    Args:
        input_csv: path to a CSV access-report file.
        provider: ``"azure-ad"`` to query Azure AD via Microsoft Graph.
        tenant_id / client_id / client_secret: Azure AD app credentials
            (can also be set via AZURE_AD_* env vars).
        days_threshold: flag accounts with no login in this many days.
        output_path: write the JSON result to this path.
        output_inactive_csv: write inactive-user findings to this CSV path.
        output_privilege_creep_csv: write privilege-creep findings to this CSV path.
    """
    if not input_csv and not provider:
        raise ValueError("Provide --input-csv <path> or --provider azure-ad.")
    if input_csv and provider:
        raise ValueError("--input-csv and --provider are mutually exclusive.")

    input_source = "csv" if input_csv else provider

    if input_csv:
        rows = load_csv(input_csv)
    else:
        rows = load_azure_ad(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

    findings = analyze_access(rows, days_threshold=days_threshold)

    summary = {
        "total_users": len(rows),
        "inactive_count": len(findings["inactive_users"]),
        "privilege_creep_count": len(findings["privilege_creep"]),
        "orphaned_approver_count": len(findings["orphaned_approvers"]),
    }

    # Derive simple compliance signals (warn if any findings)
    compliance = {
        "soc2_cc6_1": "warn" if summary["inactive_count"] > 0 else "pass",
        "iso27001_a9_2_5": "warn" if summary["privilege_creep_count"] > 0 else "pass",
    }

    result: dict[str, Any] = {
        "command": "scan access",
        "generated_at": datetime.now(UTC).isoformat(),
        "input_source": input_source,
        "days_threshold": days_threshold,
        "findings": findings,
        "summary": summary,
        "compliance": compliance,
    }

    if output_path:
        out = Path(output_path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if output_inactive_csv and findings["inactive_users"]:
        _write_findings_csv(
            output_inactive_csv,
            findings["inactive_users"],
            ["user_id", "email", "role", "last_login", "days_inactive", "recommendation"],
        )

    if output_privilege_creep_csv and findings["privilege_creep"]:
        _write_findings_csv(
            output_privilege_creep_csv,
            findings["privilege_creep"],
            ["user_id", "email", "issue"],
        )

    return result
