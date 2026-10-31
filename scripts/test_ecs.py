"""Test ECS-format parsing with the hackathon EDR generator output."""
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app import db
from app.ingest import pipeline
from app.analysis import engine
from app.ingest.parsers import parse_jsonl_line
from datetime import datetime


def main():
    root = Path(__file__).resolve().parent.parent
    out = Path(tempfile.gettempdir()) / "edr_ecs_test.json"
    proc = subprocess.run(
        [sys.executable, str(root / "edr_log_generator.py"), "--count", "600",
         "--output", "file", "--file", str(out), "--rate", "0",
         "--alert-ratio", "0.12", "--seed", "42"],
        capture_output=True, text=True, timeout=60)
    print("generator:", proc.stderr.strip())

    now = datetime.now()
    ok = err = 0
    types = {}
    rules = set()
    for line in out.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = parse_jsonl_line(line, now)
        if ev is None:
            err += 1
            continue
        ok += 1
        types[ev["event_type"]] = types.get(ev["event_type"], 0) + 1
        d = ev.get("details") or {}
        if d.get("edr_rule"):
            rules.add((d["edr_rule"], tuple(d.get("edr_mitre", [])), ev["severity"]))
    print(f"parsed ok={ok} errors={err}")
    print("types:", types)
    print("edr tagged rules:")
    for r in sorted(rules):
        print("  ", r)

    # full pipeline through db
    if (Path("data") / "killchain.db").exists():
        Path("data/killchain.db").unlink()
    db.init_db()
    job = pipeline.start_ingestion(out, "edr_events.json (ECS)", "jsonl", origin="edr_gen")
    for _ in range(100):
        j = pipeline.JOBS.get(job)
        if j and j["status"] != "running":
            break
        time.sleep(0.05)
    print("ingest job:", pipeline.JOBS.get(job))
    res = engine.run_analysis(is_demo=True)
    print("analysis:", res)
    conn = db.get_db()
    for r in conn.execute("SELECT rule_id, title, severity, mitre, killchain_stage FROM detections"):
        print(f"  [{r['severity']}] {r['rule_id']} {r['title']} {r['mitre']} stage={r['killchain_stage']}")
    for r in conn.execute("SELECT ref, risk_score, severity, name FROM incidents"):
        print(f"  {r['ref']} risk={r['risk_score']} sev={r['severity']} :: {r['name']}")


if __name__ == "__main__":
    main()
