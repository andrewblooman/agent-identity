"""SQLite storage. Each scan is one immutable row holding its snapshot and results."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from agent_identity.models import Result, Snapshot


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mode: Mapped[str] = mapped_column(String(10), index=True)
    status: Mapped[str] = mapped_column(String(20))  # running, complete or failed
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    coverage_pct: Mapped[int | None] = mapped_column(Integer, nullable=True)
    agent_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finding_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    taken_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def snapshot(self) -> Snapshot:
        return Snapshot.model_validate_json(self.snapshot_json or "{}")

    def result(self) -> Result:
        return Result.model_validate_json(self.result_json or "{}")


def create_db(path: Path) -> Engine:
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return engine


def start_scan(engine: Engine, mode: str) -> int:
    with Session(engine) as session:
        scan = Scan(mode=mode, status="running", started_at=datetime.now(UTC))
        session.add(scan)
        session.commit()
        return scan.id


def finish_scan(engine: Engine, scan_id: int, snapshot: Snapshot, result: Result) -> None:
    with Session(engine) as session:
        scan = session.get_one(Scan, scan_id)
        scan.status = "complete"
        scan.finished_at = datetime.now(UTC)
        scan.taken_at = snapshot.taken_at
        scan.snapshot_json = snapshot.model_dump_json()
        scan.result_json = result.model_dump_json()
        scan.score = result.score
        scan.coverage_pct = result.coverage_pct
        scan.agent_count = len(snapshot.agents)
        scan.finding_count = len(result.findings)
        session.commit()


def fail_scan(engine: Engine, scan_id: int, error: str) -> None:
    with Session(engine) as session:
        scan = session.get_one(Scan, scan_id)
        scan.status = "failed"
        scan.finished_at = datetime.now(UTC)
        scan.error = error
        session.commit()


def fail_interrupted_scans(engine: Engine) -> None:
    """A scan still marked running at startup died with the previous process."""
    with Session(engine) as session:
        for scan in session.scalars(select(Scan).where(Scan.status == "running")):
            scan.status = "failed"
            scan.finished_at = datetime.now(UTC)
            scan.error = "The app stopped before this scan finished. Run it again."
        session.commit()


def latest_scan(engine: Engine, mode: str) -> Scan | None:
    with Session(engine) as session:
        return session.scalars(
            select(Scan)
            .where(Scan.mode == mode, Scan.status == "complete")
            .order_by(Scan.taken_at.desc(), Scan.id.desc())
            .limit(1)
        ).first()


def previous_scan(engine: Engine, mode: str, before: Scan) -> Scan | None:
    with Session(engine) as session:
        return session.scalars(
            select(Scan)
            .where(Scan.mode == mode, Scan.status == "complete", Scan.taken_at < before.taken_at)
            .order_by(Scan.taken_at.desc())
            .limit(1)
        ).first()


def scan_history(engine: Engine, mode: str | None = None, limit: int = 50) -> list[Scan]:
    query = select(Scan).order_by(Scan.started_at.desc()).limit(limit)
    if mode:
        query = query.where(Scan.mode == mode)
    with Session(engine) as session:
        return list(session.scalars(query))


def running_scan(engine: Engine) -> Scan | None:
    with Session(engine) as session:
        return session.scalars(select(Scan).where(Scan.status == "running").limit(1)).first()


def has_scans(engine: Engine, mode: str) -> bool:
    with Session(engine) as session:
        return (
            session.scalars(select(Scan.id).where(Scan.mode == mode).limit(1)).first() is not None
        )
