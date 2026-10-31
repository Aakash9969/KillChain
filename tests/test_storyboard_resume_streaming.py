import time
from pathlib import Path

from app import config, db
from app.ingest.pipeline import JOBS, start_ingestion
from app.analysis import detectors
from app.analysis.correlate import build_incidents
from app.analysis.storyboard import build_storyboard
from app.analysis.lookahead import build_lookahead
from app.analysis.engine import run_analysis

from conftest import ev
from test_parsers_detectors import _mk_events


# ---------------------------------------------------------------------------
# Storyboard & look-ahead invariants
# ---------------------------------------------------------------------------
def test_storyboard_chronological_and_no_fabricated_stages(fresh_db):
    evs = _mk_events()
    dets = detectors.run_all_detectors(evs)
    incs = build_incidents(evs, dets, 1, True)
    dets_main = incs[0].pop("_detections")
    sb = build_storyboard(incs[0], evs, dets_main)
    order = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation",
             "Installation", "Command and Control", "Actions on Objectives"]
    stages = [p["stage"] for p in sb["phases"]]
    assert stages == sorted(stages, key=order.index), "phases must follow kill-chain order"
    for p in sb["phases"]:
        tss = [i["ts"] for i in p["items"]]
        assert tss == sorted(tss), "storyboard items must be chronological"
        for it in p["items"]:
            assert it["event_ids"] or it.get("aggregate"), "items must cite evidence"
    assert "Weaponization" in sb["unsupported_stages"], \
        "stages without evidence must be listed as gaps, never fabricated"


def test_lookahead_inference_labels_and_no_fabrication(fresh_db):
    evs = _mk_events()
    dets = detectors.run_all_detectors(evs)
    la = build_lookahead(evs, dets)
    assert la["targets"]
    t = la["targets"][0]
    assert t["inference"] is True and not t["observed"]
    assert "INFERRED" in t["label"].upper()
    assert t["evidence_event_ids"]
    labels = [x["target"]["label"] for x in la["targets"]]
    assert any("10.20.6.30" in l or "FILESRV" in l for l in labels), \
        "the probed-but-not-accessed host must appear as a potential target"
    assert la["missing_information"], "missing-information statements are required"
    assert all("compromised" not in x["label"].lower() for x in la["targets"]), \
        "potential targets must never be labelled as confirmed compromises"


# ---------------------------------------------------------------------------
# Folder ingestion resume + evidence preservation
# ---------------------------------------------------------------------------
def test_folder_resume_no_duplicates_and_raw_evidence(fresh_db, tmp_path):
    from app.ingest import folder
    lines = [f'date=2026-10-23 time=08:{m // 60:02d}:{m % 60:02d}:00 '
             f'eventtime={1792745280 + m * 60}000000000 '
             f'devname="FGT" logid="0100032002" type="event" subtype="system" level="alert" '
             f'user="u{m % 3}" action="login" status="failed" srcip=45.74.28.{m} '
             f'msg="Admin login failed"' for m in range(20)]
    p = tmp_path / "fg.log"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    conn = db.get_db()
    job_id = "testjob1"
    conn.execute("""INSERT INTO ingest_jobs (id, filename, origin, status, source_dir, resumable)
                    VALUES (?,?,?,?,?,1)""",
                 (job_id, "folder test", "folder", "running", str(tmp_path)))
    conn.execute("""INSERT INTO ingest_files (job_id, path, name, format, byte_size, status)
                    VALUES (?,?,?,?,?, 'pending')""",
                 (job_id, str(p), "fg.log", "fortigate", p.stat().st_size))
    conn.commit()
    frow = dict(conn.execute("SELECT * FROM ingest_files WHERE job_id=?", (job_id,)).fetchone())

    # interrupted first session: file only contained the first 7 lines
    full = p.read_bytes()
    p.write_bytes(("\n".join(lines[:7]) + "\n").encode())
    folder._process_file(job_id, frow, time.time())
    row = dict(conn.execute("SELECT * FROM ingest_files WHERE job_id=?", (job_id,)).fetchone())
    assert row["status"] == "done" and row["parsed_events"] == 7
    committed_offset = row["byte_offset"]

    # file grows to full size -> fresh re-ingest reads everything
    p.write_bytes(full)
    conn.execute("DELETE FROM events")
    conn.execute("UPDATE ingest_files SET status='pending', byte_offset=0, line_no=0, "
                 "parsed_events=0 WHERE id=?", (frow["id"],))
    conn.commit()
    folder._process_file(job_id, frow, time.time())
    n = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    assert n == 20, f"full re-ingest should give 20 events, got {n}"

    # resume semantics: starting from the committed offset reads only the tail
    conn.execute("DELETE FROM events")
    conn.execute("UPDATE ingest_files SET status='pending', byte_offset=?, line_no=7, "
                 "parsed_events=7 WHERE id=?", (committed_offset, frow["id"]))
    conn.commit()
    frow = dict(conn.execute("SELECT * FROM ingest_files WHERE id=?", (frow["id"],)).fetchone())
    folder._process_file(job_id, frow, time.time())
    n = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    assert n == 13, f"resume from checkpoint should read only the remaining 13, got {n}"
    raw = conn.execute("SELECT raw FROM events LIMIT 1").fetchone()["raw"]
    assert raw.startswith("date=2026-10-23"), "raw evidence must be preserved"


def test_path_allowlist_blocks_outside_roots():
    from app.ingest.folder import path_allowed
    assert path_allowed(config.DATA_DIR / "sub" / "file.log")
    assert not path_allowed(Path("C:/Windows/system32/config"))


# ---------------------------------------------------------------------------
# Streaming (SQL-first) analysis equivalence on a small dataset
# ---------------------------------------------------------------------------
def test_streaming_analysis_equivalent_to_full(fresh_db, monkeypatch):
    lines = []
    for k in range(40):
        lines.append(f'date=2026-10-23 time=08:{k // 60:02d}:{k % 60:02d}:00 '
                     f'eventtime={1792745280 + k * 60}000000000 '
                     f'devname="FGT" logid="0100032002" type="event" subtype="system" '
                     f'level="alert" user="victim" action="login" status="failed" '
                     f'srcip=45.74.28.9 msg="Admin login failed from 45.74.28.9"')
    lines.append('date=2026-10-23 time=09:10:00 eventtime=1792749000000000000 devname="FGT" '
                 'logid="0100032001" type="event" subtype="system" level="information" '
                 'user="victim" action="login" status="success" srcip=45.74.28.9 '
                 'msg="Admin login successful"')
    p = Path(config.DATA_DIR) / "stream_test.log"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    job = start_ingestion(p, "stream_test.log", "fortigate", origin="folder")
    for _ in range(200):
        j = JOBS.get(job)
        if j and j["status"] != "running":
            break
        time.sleep(0.05)
    conn = db.get_db()
    n = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    assert n == 41

    res_full = run_analysis(is_demo=False)
    assert res_full["mode"] == "full"
    full_rules = {r["rule_id"] for r in conn.execute(
        "SELECT rule_id FROM detections WHERE analysis_id=?", (res_full["analysis_id"],))}

    # second run with a tiny threshold exercises the SQL-first streaming path
    monkeypatch.setattr(config, "FULL_SCAN_LIMIT", 20)
    res_stream = run_analysis(is_demo=False)
    assert res_stream["mode"] == "streaming"
    stream_rules = {r["rule_id"] for r in conn.execute(
        "SELECT rule_id FROM detections WHERE analysis_id=?", (res_stream["analysis_id"],))}

    assert "SUCCESS_AFTER_FAILURES" in full_rules, \
        "full path must detect success-after-failures"
    assert "SUCCESS_AFTER_FAILURES" in stream_rules, \
        "streaming path must reach the same conclusion"
    assert "AUTH_TARGETED_BRUTE" in stream_rules or "BRUTE_FORCE_AUTH" in stream_rules
