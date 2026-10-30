"""Fail-closed staging boundaries, with no network or database operations."""
from __future__ import annotations

from collections.abc import Mapping
import os
import re
from urllib.parse import urlsplit

from psycopg.conninfo import conninfo_to_dict
from pydantic import EmailStr, TypeAdapter, ValidationError


class StagingConfigurationError(RuntimeError):
    """Unsafe or incomplete staging settings; messages never include values."""


_EMAIL = TypeAdapter(EmailStr)
_CONFIGURATION_ERROR = "Staging configuration is invalid."


def _settings(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def _is_staging(environ: Mapping[str, str]) -> bool:
    return environ.get("APP_ENV", "").strip().lower() == "staging"


def _invalid() -> None:
    raise StagingConfigurationError(_CONFIGURATION_ERROR)


def _project_ref(value: str) -> str:
    reference = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", reference):
        _invalid()
    return reference


def _https_origin(value: str) -> str:
    value = value.strip()
    if not value or "*" in value or any(character.isspace() for character in value):
        _invalid()
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        if (parsed.scheme != "https" or not hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment or port == 0):
            _invalid()
        # Reject ambiguous/encoded host spellings instead of letting browser
        # URL normalization turn a declared stage origin into another target.
        if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                   for label in hostname.lower().split(".")):
            _invalid()
    except ValueError:
        raise StagingConfigurationError(_CONFIGURATION_ERROR) from None
    return f"https://{hostname.lower()}" + (f":{port}" if port not in {None, 443} else "")


def _origin_list(value: str) -> set[str]:
    return {_https_origin(origin) for origin in value.split(",")}


def _email_address(value: str) -> str:
    address = value.strip()
    if not address or any(character in address for character in "*<>,;\r\n"):
        _invalid()
    try:
        parsed = str(_EMAIL.validate_python(address))
    except ValidationError:
        raise StagingConfigurationError(_CONFIGURATION_ERROR) from None
    # Accept only an address, never a display-name or recipient-list syntax.
    if parsed.lower() != address.lower():
        _invalid()
    return parsed.lower()


def _email_allowlist(environ: Mapping[str, str]) -> set[str]:
    return {_email_address(address) for address in environ.get("STAGING_EMAIL_ALLOWLIST", "").split(",")}


def _validate_database_target(database_url: str, stage_ref: str, environ: Mapping[str, str]) -> None:
    # libpq parsing observes effective URI query overrides (e.g. ?host=...),
    # decodes credentials and performs no DNS lookup or connection.
    value = database_url.strip().strip('"').strip("'")
    if not value.startswith(("postgresql://", "postgres://")):
        _invalid()
    try:
        parameters = conninfo_to_dict(value)
    except Exception:
        raise StagingConfigurationError(_CONFIGURATION_ERROR) from None
    if (any(parameters.get(name) for name in ("hostaddr", "service"))
            or environ.get("PGHOSTADDR") or environ.get("PGSERVICE")):
        _invalid()
    hostname = parameters.get("host", "").lower()
    username = parameters.get("user", "")
    if parameters.get("port", "5432") != "5432":
        _invalid()
    direct = hostname == f"db.{stage_ref}.supabase.co"
    pooler = bool(re.fullmatch(r"[a-z0-9][a-z0-9-]*\.pooler\.supabase\.com", hostname))
    if not direct and not (pooler and username == f"postgres.{stage_ref}"):
        _invalid()


def validate_staging_configuration(database_url: str, *, environ: Mapping[str, str] | None = None) -> None:
    """Validate staging destinations before bootstrap can mutate any database."""
    settings = _settings(environ)
    if not _is_staging(settings):
        return
    stage_ref = _project_ref(settings.get("STAGING_DATABASE_PROJECT_REF", ""))
    production_ref = _project_ref(settings.get("PRODUCTION_DATABASE_PROJECT_REF", ""))
    if stage_ref == production_ref:
        _invalid()
    _validate_database_target(database_url, stage_ref, settings)
    origin = _https_origin(settings.get("STAGING_SITE_ORIGIN", ""))
    production_origins = _origin_list(settings.get("PRODUCTION_SITE_ORIGINS", ""))
    if (origin in production_origins or _https_origin(settings.get("FRONTEND_URL", "")) != origin
            or _origin_list(settings.get("BACKEND_CORS_ORIGINS", "")) != {origin}
            or settings.get("BACKEND_ALLOW_LOCAL_ORIGINS", "true").strip().lower() not in {"0", "false", "no"}):
        _invalid()
    _email_allowlist(settings)


def require_allowed_staging_recipient(to_email: str, *, environ: Mapping[str, str] | None = None) -> None:
    """Block unlisted recipients before either email provider can be called."""
    settings = _settings(environ)
    if not _is_staging(settings):
        return
    if _email_address(to_email) not in _email_allowlist(settings):
        raise StagingConfigurationError("Staging email recipient is not allowed.")
