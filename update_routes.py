"""Application release/update metadata routes."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Query

from admin_routes import require_admin
from database import get_db
from models import ApiResponse, AppReleaseUpdateRequest

router = APIRouter(tags=["App updates"])
PUBLIC_CHANGELOG_LIMIT = 2


def _version_parts(value: str | None) -> tuple[int, ...]:
    """Convert a semantic-ish version string into comparable integer parts."""
    if not value:
        return ()
    parts = re.findall(r"\d+", str(value))
    return tuple(int(part) for part in parts[:4])


def _is_newer(latest: str | None, current: str | None) -> bool:
    latest_parts = _version_parts(latest)
    current_parts = _version_parts(current)
    width = max(len(latest_parts), len(current_parts), 1)
    latest_parts += (0,) * (width - len(latest_parts))
    current_parts += (0,) * (width - len(current_parts))
    return latest_parts > current_parts


def _release_to_public(row: dict, current_version: str | None = None) -> dict:
    """Return release metadata in the shape consumed by desktop and web."""
    min_supported = row.get("min_supported_version")
    below_minimum = bool(current_version and min_supported and _is_newer(min_supported, current_version))
    update_available = bool(current_version and (_is_newer(row.get("version"), current_version) or below_minimum))

    return {
        "ok": True,
        "channel": row["channel"],
        "current_version": current_version,
        "latest_version": row["version"],
        "min_supported_version": min_supported,
        "download_url": row["download_url"],
        "release_notes": row.get("release_notes") or "",
        "sha256": row.get("sha256"),
        "installer_filename": row.get("installer_filename") or "GeoMapperProSetup.exe",
        "installer_size_bytes": row.get("installer_size_bytes"),
        "required": bool(row.get("required")) or below_minimum,
        "update_available": update_available,
        "published_at": row["published_at"].isoformat() if row.get("published_at") else None,
    }


def get_active_release(channel: str = "stable") -> dict | None:
    """Load the active release row for a channel, falling back to stable."""
    channel = (channel or "stable").strip().lower()
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT id, channel, version, min_supported_version, download_url,
                   release_notes, sha256, installer_filename,
                   installer_size_bytes, required, published_at
            FROM app_releases
            WHERE channel = %s
              AND is_active = TRUE
            ORDER BY published_at DESC, id DESC
            LIMIT 1
            """,
            (channel,),
        ).fetchone()

        if row or channel == "stable":
            return row

        return conn.execute(
            """
            SELECT id, channel, version, min_supported_version, download_url,
                   release_notes, sha256, installer_filename,
                   installer_size_bytes, required, published_at
            FROM app_releases
            WHERE channel = 'stable'
              AND is_active = TRUE
            ORDER BY published_at DESC, id DESC
            LIMIT 1
            """
        ).fetchone()


@router.get("/app/version")
def app_version(
    current_version: str | None = Query(default=None),
    channel: str = Query(default="stable"),
):
    """Return latest desktop release metadata for update checks."""
    release = get_active_release(channel)
    if not release:
        return {
            "ok": False,
            "message": "No active app release is configured.",
        }
    return _release_to_public(release, current_version)


@router.get("/app/changelog")
def app_changelog(channel: str = Query(default="stable")):
    """Return public release history for the changelog page."""
    channel = (channel or "stable").strip().lower()
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, channel, version, min_supported_version, download_url,
                   release_notes, sha256, installer_filename,
                   installer_size_bytes, required, published_at
            FROM app_releases
            WHERE channel = %s
            ORDER BY published_at DESC, id DESC
            LIMIT %s
            """,
            (channel, PUBLIC_CHANGELOG_LIMIT),
        ).fetchall()
    return {
        "ok": True,
        "releases": [_release_to_public(row) for row in rows],
    }


@router.get("/admin/app-release")
def admin_get_app_release(
    channel: str = Query(default="stable"),
    _: dict = Depends(require_admin),
):
    """Return the active release metadata for administrators."""
    release = get_active_release(channel)
    if not release:
        return {
            "ok": False,
            "message": "No active app release is configured.",
        }
    return _release_to_public(release)


@router.put("/admin/app-release", response_model=ApiResponse)
def admin_set_app_release(
    payload: AppReleaseUpdateRequest,
    _: dict = Depends(require_admin),
):
    """Publish a new active release row for a channel."""
    channel = payload.channel.strip().lower()

    with get_db() as conn:
        conn.execute(
            """
            UPDATE app_releases
            SET is_active = FALSE
            WHERE channel = %s
              AND is_active = TRUE
            """,
            (channel,),
        )
        conn.execute(
            """
            INSERT INTO app_releases (
                channel,
                version,
                min_supported_version,
                download_url,
                release_notes,
                sha256,
                installer_filename,
                installer_size_bytes,
                required,
                is_active
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
            """,
            (
                channel,
                payload.version.strip(),
                payload.min_supported_version.strip() if payload.min_supported_version else None,
                payload.download_url.strip(),
                payload.release_notes.strip(),
                payload.sha256.strip() if payload.sha256 else None,
                payload.installer_filename.strip() if payload.installer_filename else "GeoMapperProSetup.exe",
                payload.installer_size_bytes,
                bool(payload.required),
            ),
        )

    return ApiResponse(ok=True, message=f"Active {channel} release set to {payload.version.strip()}.")
