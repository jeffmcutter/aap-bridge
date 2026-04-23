"""Parse and apply team role grants (team as principal on other resources)."""

from __future__ import annotations

from typing import Any

from aap_migration.resources import normalize_resource_type
from aap_migration.utils.logging import get_logger

logger = get_logger(__name__)

# Built-in roles on the team object itself; recreated with the team on target.
_TEAM_SELF_ROLE_NAMES = frozenset(
    {
        "member",
        "admin",
        "read",
    }
)


def _norm_role_name(s: str | None) -> str:
    return (s or "").strip().casefold()


def parse_team_role_from_api(
    role: dict[str, Any],
    *,
    team_source_id: int,
) -> dict[str, str | int] | None:
    """Extract grant info from a Role row in ``GET /teams/{id}/roles/`` (or object_roles list).

    Returns a dict with role_name, content_resource_type (canonical), content_source_id,
    or None to skip.
    """
    if not role:
        return None

    name = role.get("name")
    if not name:
        return None

    summary = role.get("summary_fields") or {}

    # 1) unified_job_template (job template vs workflow)
    ujt = summary.get("unified_job_template")
    if isinstance(ujt, dict) and ujt.get("id") is not None:
        uj_type = (ujt.get("unified_job_type") or ujt.get("type") or "").lower()
        if "workflow" in uj_type:
            rtype = "workflow_job_templates"
        else:
            rtype = "job_templates"
        return {
            "role_name": str(name).strip(),
            "content_resource_type": rtype,
            "content_source_id": int(ujt["id"]),
        }

    # 2) known summary field keys (AWX / AAP 2.3–2.6)
    field_to_type: list[tuple[str, str]] = [
        ("project", "projects"),
        ("organization", "organizations"),
        ("inventory", "inventory"),
        ("credential", "credentials"),
        ("job_template", "job_templates"),
        ("workflow_job_template", "workflow_job_templates"),
        ("instance_group", "instance_groups"),
        ("execution_environment", "execution_environments"),
        ("notification_template", "notification_templates"),
        ("team", "teams"),
    ]

    for field, rtype in field_to_type:
        obj = summary.get(field)
        if not isinstance(obj, dict) or obj.get("id") is None:
            continue
        rid = int(obj["id"])
        # Skip built-in team-object roles (Member/Admin/Read) on *this* team
        rtype = normalize_resource_type(rtype)
        if rtype == "teams" and rid == team_source_id and _norm_role_name(str(name)) in _TEAM_SELF_ROLE_NAMES:
            return None
        return {
            "role_name": str(name).strip(),
            "content_resource_type": rtype,
            "content_source_id": rid,
        }

    # 3) Flat resource_type + resource_id (AAP 2.3 GET /teams/{id}/roles/ format).
    #    summary_fields has: resource_type="job_template", resource_id=7  (no nested dict)
    #    Also handles the generic "resource" nested dict used by some older AWX versions.
    type_map: dict[str, str] = {
        "job_template": "job_templates",
        "project": "projects",
        "workflow_job_template": "workflow_job_templates",
        "credential": "credentials",
        "inventory": "inventory",
        "organization": "organizations",
        "team": "teams",
        "instance_group": "instance_groups",
        "execution_environment": "execution_environments",
        "notification_template": "notification_templates",
        # display-name variants (space-separated, from resource_type_display_name)
        "job template": "job_templates",
        "workflow job template": "workflow_job_templates",
        "instance group": "instance_groups",
        "execution environment": "execution_environments",
        "notification template": "notification_templates",
    }

    rtype_str = (summary.get("resource_type") or summary.get("resource_type_display_name") or "")
    if isinstance(rtype_str, dict):
        rtype_str = rtype_str.get("name", "") or rtype_str.get("type", "")
    rtype_str = str(rtype_str).strip().lower()

    # Flat integer resource_id (AAP 2.3)
    flat_rid = summary.get("resource_id")
    if rtype_str and flat_rid is not None:
        canonical = type_map.get(rtype_str)
        if canonical:
            canonical = normalize_resource_type(canonical)
            rid = int(flat_rid)
            if canonical == "teams" and rid == team_source_id and _norm_role_name(str(name)) in _TEAM_SELF_ROLE_NAMES:
                return None
            return {
                "role_name": str(name).strip(),
                "content_resource_type": canonical,
                "content_source_id": rid,
            }

    # Nested resource dict (some older AWX versions)
    res = summary.get("resource")
    if rtype_str and isinstance(res, dict) and res.get("id") is not None:
        canonical = type_map.get(rtype_str)
        if canonical:
            rid = int(res["id"])
            canonical = normalize_resource_type(canonical)
            if canonical == "teams" and rid == team_source_id and _norm_role_name(str(name)) in _TEAM_SELF_ROLE_NAMES:
                return None
            return {
                "role_name": str(name).strip(),
                "content_resource_type": canonical,
                "content_source_id": rid,
            }

    logger.debug(
        "team_role_grant_unparsed",
        team_source_id=team_source_id,
        role_id=role.get("id"),
        role_name=name,
    )
    return None
