"""Export a checkpointed audit run to JSON for the dashboard.

Reads ``.redforge_work/<run_id>/graph.sqlite``. Does not run the pipeline.

The events array is one entry per graph node, in completion order. Timestamps
and durations come from the LangGraph checkpoints that bracket each node.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from langgraph.checkpoint.sqlite import SqliteSaver

from redforge.schemas import AuditState, AuditStatus

NODE_ORDER = ("scout", "strategist", "poc", "remediation", "verification")


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _status_value(status: AuditStatus | str | None) -> str:
    if status is None:
        return ""
    return status.value if isinstance(status, AuditStatus) else str(status)


def _load(db: Path, thread_id: str) -> tuple[AuditState, list]:
    with SqliteSaver.from_conn_string(str(db)) as cp:
        config = {"configurable": {"thread_id": thread_id}}
        rows = list(cp.list(config))
    rows.reverse()
    if not rows:
        raise SystemExit(f"no checkpoints for thread {thread_id} in {db}")
    values = rows[-1].checkpoint.get("channel_values") or {}
    data = {
        key: value
        for key, value in values.items()
        if not key.startswith("branch") and not key.startswith("__")
    }
    return AuditState.model_validate(data), rows


def _node_for_pending(channels: set[str], next_status: str) -> str | None:
    # The input checkpoint also writes empty findings/functions. Scout is the
    # step that routes onward to the strategist.
    if "branch:to:strategist" in channels:
        return "scout"
    if "branch:to:poc" in channels:
        return "strategist"
    if "branch:to:remediation" in channels:
        return "poc"
    if "branch:to:verification" in channels:
        return "remediation"
    if next_status == AuditStatus.VERIFIED.value:
        return "verification"
    return None


def _summary(node: str, state: AuditState) -> str:
    if node == "scout":
        return f"{len(state.findings)} findings, {len(state.functions)} functions"
    if node == "strategist":
        if not state.hypotheses:
            return "0 hypotheses"
        top = max(state.hypotheses, key=lambda h: h.priority)
        return (
            f"{len(state.hypotheses)} hypotheses; "
            f"top {top.target_contract}.{top.target_function} "
            f"priority {top.priority}"
        )
    confirmed = next(
        (v for v in state.vulnerabilities if v.poc and v.poc.oracle_confirmed),
        None,
    )
    if node == "poc":
        if confirmed is None or confirmed.poc is None or confirmed.hypothesis is None:
            return f"{len(state.vulnerabilities)} vulnerabilities, none confirmed"
        hyp = confirmed.hypothesis
        poc = confirmed.poc
        return (
            f"{hyp.id} {hyp.target_contract}.{hyp.target_function} "
            f"confirmed on attempt {poc.attempt} (oracle {poc.oracle.value})"
        )
    if node == "remediation":
        patch = confirmed.patch if confirmed else None
        if patch is None:
            return "no patch"
        return (
            f"{patch.contract} compiles={str(patch.compiles).lower()} "
            f"poc_defeated={str(patch.poc_defeated).lower()} "
            f"attempts={patch.attempts}"
        )
    if node == "verification":
        report = confirmed.verification if confirmed else None
        if report is None:
            return "no verification report"
        return (
            f"verified={str(report.verified).lower()} "
            f"differential={str(report.differential_equivalent).lower()} "
            f"halmos_proved={str(report.halmos_proved).lower()} "
            f"existing_tests_pass={str(report.existing_tests_pass).lower()}"
        )
    return node


def _events(state: AuditState, rows: list) -> list[dict]:
    events: list[dict] = []
    for index, tup in enumerate(rows[:-1]):
        pending = {write[1] for write in (tup.pending_writes or [])}
        nxt = rows[index + 1]
        nxt_values = nxt.checkpoint.get("channel_values") or {}
        nxt_status = _status_value(nxt_values.get("status"))
        node = _node_for_pending(pending, nxt_status)
        if node is None:
            continue
        started = _parse_ts(tup.checkpoint["ts"])
        finished = _parse_ts(nxt.checkpoint["ts"])
        events.append(
            {
                "node": node,
                "status": nxt_status,
                "summary": _summary(node, state),
                "timestamp": nxt.checkpoint["ts"],
                "duration_s": round((finished - started).total_seconds(), 3),
            }
        )
    # Keep pipeline order if a checkpoint walk ever emits extras.
    rank = {name: i for i, name in enumerate(NODE_ORDER)}
    events.sort(key=lambda event: rank.get(event["node"], 99))
    return events


def export_run(run_id: str, db: Path, dest: Path) -> dict:
    state, rows = _load(db, run_id)
    payload = state.model_dump(mode="json")
    payload["events"] = _events(state, rows)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _describe(payload: dict, dest: Path) -> None:
    raw = dest.read_bytes()
    print(f"wrote {dest} ({len(raw)} bytes)")
    print("top-level keys:", ", ".join(payload.keys()))
    for key in ("findings", "functions", "hypotheses", "vulnerabilities", "events", "errors"):
        value = payload.get(key)
        if isinstance(value, list):
            print(f"  {key}: {len(value)}")
    print(f"  status: {payload.get('status')}")
    print(f"  token_cost_usd: {payload.get('token_cost_usd')}")
    if payload.get("hypotheses"):
        hyp = payload["hypotheses"][0]
        print("  hypothesis keys:", ", ".join(hyp.keys()))
    if payload.get("vulnerabilities"):
        vuln = payload["vulnerabilities"][0]
        print("  vulnerability keys:", ", ".join(vuln.keys()))
        for part in ("poc", "patch", "verification"):
            body = vuln.get(part) or {}
            sizes = {
                field: len(text) if isinstance(text, str) else text
                for field, text in body.items()
            }
            print(f"  {part}: {sizes}")
    for event in payload.get("events", []):
        print(
            f"  event {event['node']}: status={event['status']} "
            f"duration_s={event['duration_s']} ts={event['timestamp']} "
            f"summary={event['summary']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="9f845086")
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="graph.sqlite path (default: .redforge_work/<run-id>/graph.sqlite)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("showcase/dvd-unstoppable-verified/run.json"),
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    db = args.db or (root / ".redforge_work" / args.run_id / "graph.sqlite")
    dest = args.out if args.out.is_absolute() else root / args.out
    payload = export_run(args.run_id, db, dest)
    _describe(payload, dest)


if __name__ == "__main__":
    main()
