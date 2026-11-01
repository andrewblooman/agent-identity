"""Shared collector plumbing: record failures as coverage gaps instead of as empty results."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError

from agent_identity.models import Coverage, CoverageStatus, Domain

log = logging.getLogger(__name__)

# What counts as "this call failed, carry on". Anything else is a bug and should stop the scan.
CALL_FAILURES: tuple[type[Exception], ...] = (ClientError, BotoCoreError)

_DENIED = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "UnauthorizedException",
    "AccessDeniedFault",
}
_THROTTLED = {
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
}
_NOT_ENABLED = {
    "SubscriptionRequiredException",
    "ResourceNotFoundException",
    "OptInRequired",
    "ValidationException",
}


@dataclass
class CoverageLog:
    entries: list[Coverage] = field(default_factory=list)

    def ok(self, source: str, region: str = "global", detail: str = "") -> None:
        self.entries.append(
            Coverage(source=source, region=region, status=CoverageStatus.OK, detail=detail)
        )

    def gap(
        self,
        source: str,
        region: str,
        status: CoverageStatus,
        detail: str,
        affects: list[Domain] | None = None,
    ) -> None:
        self.entries.append(
            Coverage(
                source=source, region=region, status=status, detail=detail, affects=affects or []
            )
        )


def status_for(error: Exception) -> tuple[CoverageStatus, str]:
    if isinstance(error, EndpointConnectionError):
        return CoverageStatus.NOT_AVAILABLE, "This service has no endpoint in this region"
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "Unknown")
        message = error.response.get("Error", {}).get("Message", "")
        # Macie answers AccessDenied when it's switched off, whatever the caller's permissions.
        if code in _DENIED and "not enabled" in message.lower():
            return CoverageStatus.NOT_ENABLED, "This service isn't turned on in this region"
        if code in _DENIED:
            operation = error.operation_name
            return CoverageStatus.ACCESS_DENIED, f"The scan profile can't call {operation}"
        if code in _THROTTLED:
            return CoverageStatus.THROTTLED, "AWS limited the request rate. Run the scan again"
        if code in _NOT_ENABLED:
            return CoverageStatus.NOT_ENABLED, f"AWS returned {code}"
        return CoverageStatus.ERROR, f"AWS returned {code}"
    return CoverageStatus.ERROR, f"{type(error).__name__} while contacting AWS"


def attempt[T](
    coverage: CoverageLog,
    source: str,
    region: str,
    call: Callable[[], T],
    default: T,
    affects: list[Domain] | None = None,
    record_ok: bool = True,
) -> tuple[T, bool]:
    """Run a collector step. Returns (value, succeeded). A blocked operation still propagates."""
    try:
        value = call()
    except CALL_FAILURES as error:
        status, detail = status_for(error)
        log.warning("%s in %s: %s", source, region, detail)
        coverage.gap(source, region, status, detail, affects)
        return default, False
    if record_ok:
        coverage.ok(source, region)
    return value, True


def quiet(call: Callable[[], Any], default: Any = None) -> Any:
    """For per-resource detail calls, where a failure just leaves that field unknown (None)."""
    try:
        return call()
    except CALL_FAILURES as error:
        log.debug("Detail call failed: %s", error)
        return default
