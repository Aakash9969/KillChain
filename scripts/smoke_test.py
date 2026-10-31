"""Headless smoke test of the KillChain pipeline (no server needed)."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app import config, db
from app.ingest import demo, pipeline
from app.analysis import engine
from app.analysis.graph import build_graph
from app.reports import build_report


def wait_jobs(job_ids):
    for _ in range(100):
        done = all(pipeline.JOBS.get(j)["status"] != "running" for j in job_ids if pipeline.JOBS.get(j))
        if done:
            break
        time.sleep(0.1)
    for j in job_ids:
        job = pipeline.JOBS.get(j)
        if job:
            print(f"  job {job['filename']}: {job['status']} lines={job['processed_lines']} "
                  f"parsed={job['parsed_events']} errors={job['parse_errors']}")


def main():
    # fresh db for the test
    if config.DB_PATH.exists():
        config.DB_PATH.unlink()
    db.init_db()

    print("== generating demo files ==")
    files = demo.generate_demo_files()
    for name, p in files.items():
        print(f"  {name}: {p.stat().st_size} bytes")

    print("== ingesting ==")
    job_ids = []
    for name, p in files.items():
        fmt = "jsonl" if name.endswith(".jsonl") else "syslog"
        job_ids.append(pipeline.start_ingestion(p, name, fmt, origin="demo"))
    wait_jobs(job_ids)

    conn = db.get_db()
    n = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    print(f"  events in db: {n}")
    for r in conn.execute("SELECT event_type, COUNT(*) c FROM events GROUP BY event_type"):
        print(f"    {r['event_type']}: {r['c']}")

    print("== running analysis ==")
    result = engine.run_analysis(is_demo=True)
    print(" ", result)

    print("== detections ==")
    for r in conn.execute("SELECT rule_id, title, severity, confidence, mitre, killchain_stage, "
                          "explanation FROM detections"):
        print(f"  [{r['severity']}] {r['rule_id']}: {r['title']} "
              f"mitre={r['mitre']} stage={r['killchain_stage']} conf={r['confidence']}")
        print(f"      {r['explanation'][:180]}")

    print("== incidents ==")
    for r in conn.execute("SELECT id, ref, name, risk_score, severity FROM incidents"):
        print(f"  {r['ref']} risk={r['risk_score']} sev={r['severity']} :: {r['name']}")

    inc = conn.execute("SELECT * FROM incidents ORDER BY risk_score DESC LIMIT 1").fetchone()
    inc = engine.get_incident(conn, inc["id"])
    events = engine.get_incident_events(conn, inc["event_ids"])
    dets = engine.get_incident_detections(conn, inc["detection_ids"])
    print(f"  top incident: {inc['ref']} events={len(events)} detections={len(dets)}")
    print(f"  entry point: {inc['entry_point']}")
    print(f"  progressions: {[p['stage'] for p in inc['progressions']]}")
    print(f"  hypotheses: {[h['label'] for h in inc['hypotheses']]}")

    g = build_graph(inc, events, dets)
    print(f"  graph: {len(g['nodes'])} nodes, {len(g['edges'])} edges")
    for e in g["edges"]:
        print(f"    {e['source']} --[{e['kind']}{'/INFERRED' if not e['observed'] else ''}]--> {e['target']}")

    report = build_report(conn, inc["id"])
    md = report["markdown"]
    print(f"== report: {len(md)} chars markdown ==")
    (Path(__file__).parent / "report_preview.md").write_text(md, encoding="utf-8")
    print("  written report_preview.md")


if __name__ == "__main__":
    main()
