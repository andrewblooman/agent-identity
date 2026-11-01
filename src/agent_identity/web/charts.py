"""Geometry for the server-rendered SVG charts. Templates draw what these return."""

from __future__ import annotations

from dataclasses import dataclass

from agent_identity.models import Trifecta


def glyph_state(value: bool | None) -> str:
    return "on" if value is True else "off" if value is False else "unknown"


def trifecta_glyph(trifecta: Trifecta) -> dict[str, str | bool]:
    return {
        "data": glyph_state(trifecta.sensitive_data.state),
        "input": glyph_state(trifecta.untrusted_input.state),
        "out": glyph_state(trifecta.outbound_path.state),
        "complete": trifecta.complete,
        "possible": trifecta.possible,
    }


def score_tone(score: int | None) -> str:
    if score is None:
        return "none"
    return "critical" if score <= 40 else "high" if score <= 70 else "good"


def gauge(score: int | None) -> dict:
    """A half-circle gauge. The arc uses pathLength=100, so the score is the dash length."""
    return {"score": score, "dash": score or 0, "tone": score_tone(score)}


def doughnut(parts: list[dict]) -> dict:
    """Segments for a ring drawn with pathLength=100. Each part needs label, count and tone."""
    total = sum(p["count"] for p in parts)
    active = [p for p in parts if p["count"]]
    gap = 1.2 if len(active) > 1 else 0
    usable = 100 - gap * len(active)
    offset = 0.0
    segments = []
    for part in active:
        length = usable * part["count"] / total
        segments.append({**part, "dash": round(length, 2), "offset": round(-offset, 2)})
        offset += length + gap
    return {"total": total, "segments": segments, "parts": parts}


@dataclass
class Node:
    id: str
    label: str
    detail: str
    tone: str
    x: float
    y: float
    href: str | None = None


@dataclass
class Edge:
    path: str
    tone: str


@dataclass
class Graph:
    width: int
    height: int
    nodes: list[Node]
    edges: list[Edge]
    columns: list[tuple[str, float]]


NODE_W, NODE_H, ROW_GAP = 190, 44, 12
COLUMN_X = (0, 245, 490, 735)
HEADER_H = 26


def _clip(text: str, limit: int = 25) -> str:
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def attack_graph(columns: list[list[dict]], edges: list[tuple[str, str]]) -> Graph:
    """Lay out four columns, entry to impact. Each node needs id, label, detail and tone."""
    tallest = max((len(c) for c in columns), default=1) or 1
    height = HEADER_H + tallest * (NODE_H + ROW_GAP)
    nodes: dict[str, Node] = {}
    for x, column in zip(COLUMN_X, columns, strict=True):
        offset = HEADER_H + (tallest - len(column)) * (NODE_H + ROW_GAP) / 2
        for index, spec in enumerate(column):
            nodes[spec["id"]] = Node(
                id=spec["id"],
                label=_clip(spec["label"]),
                detail=_clip(spec.get("detail", ""), 30),
                tone=spec.get("tone", "neutral"),
                x=x,
                y=round(offset + index * (NODE_H + ROW_GAP), 1),
                href=spec.get("href"),
            )
    drawn = []
    for source, target in edges:
        a, b = nodes.get(source), nodes.get(target)
        if a is None or b is None:
            continue
        x1, y1 = a.x + NODE_W, a.y + NODE_H / 2
        x2, y2 = b.x, b.y + NODE_H / 2
        mid = (x1 + x2) / 2
        drawn.append(
            Edge(
                f"M{x1} {y1} C{mid} {y1} {mid} {y2} {x2} {y2}",
                "hot" if b.tone == "critical" else "plain",
            )
        )
    titles = ("How it gets in", "The agent", "What it acts as", "What it can reach")
    return Graph(
        width=COLUMN_X[-1] + NODE_W,
        height=int(height),
        nodes=list(nodes.values()),
        edges=drawn,
        columns=list(zip(titles, COLUMN_X, strict=True)),
    )
