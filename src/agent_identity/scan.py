"""Run scans and store the results."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from sqlalchemy import delete
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from agent_identity import db
from agent_identity.analysis.engine import analyse
from agent_identity.config import Settings
from agent_identity.demo.estate import HISTORY_DAYS_AGO, build_snapshot

log = logging.getLogger(__name__)


def seed_demo(engine: Engine) -> None:
    """Rebuild the demo history, so its dates stay relative to today."""
    with Session(engine) as session:
        session.execute(delete(db.Scan).where(db.Scan.mode == "demo"))
        session.commit()
    now = datetime.now(UTC)
    for days_ago in HISTORY_DAYS_AGO:
        scan_id = db.start_scan(engine, "demo")
        snapshot = build_snapshot(days_ago, now=now)
        db.finish_scan(engine, scan_id, snapshot, analyse(snapshot, now=snapshot.taken_at))


def _explain(error: Exception) -> str:
    if isinstance(error, NoCredentialsError):
        return "No AWS credentials found. Check AWS_PROFILE in .env and that ~/.aws is mounted."
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "Unknown")
        if code in {"ExpiredToken", "ExpiredTokenException", "RequestExpired"}:
            return "Your AWS session has expired. Sign in again, then run the scan."
        if code in {"InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch"}:
            return "AWS rejected these credentials. Check AWS_PROFILE in .env."
        return f"AWS returned {code} during the scan."
    if isinstance(error, BotoCoreError):
        return f"Could not reach AWS: {type(error).__name__}."
    return f"The scan stopped because of an internal error: {type(error).__name__}."


def run_live_scan(engine: Engine, settings: Settings, scan_id: int) -> None:
    from agent_identity.aws.collect import collect_snapshot

    try:
        snapshot = collect_snapshot(settings)
        db.finish_scan(engine, scan_id, snapshot, analyse(snapshot))
    except Exception as error:  # A background thread has nowhere else to report this.
        log.exception("Live scan %s failed", scan_id)
        db.fail_scan(engine, scan_id, _explain(error))
