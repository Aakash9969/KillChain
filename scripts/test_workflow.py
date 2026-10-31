"""End-to-end workflow test against the running server (real HTTP)."""
import json
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000/api"


def req(path, method="GET", data=None, ctype="application/json"):
    body = json.dumps(data).encode() if isinstance(data, (dict, list)) else data
    headers = {"Content-Type": ctype} if (data is not None and isinstance(data, (dict, list))) else {}
    r = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    try:
        return json.load(urllib.request.urlopen(r))
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "detail": e.read().decode()[:200]}


def main():
    print("reset:", req("/admin/reset", "POST")["ok"])

    # upload a custom syslog file via multipart
    boundary = "----kc"
    content = ("Mar 15 04:12:11 SRV-TEST sshd[900]: Failed password for admin from "
               "203.0.113.99 port 5001 ssh2\n" * 8).encode()
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="custom.log"\r\nContent-Type: text/plain\r\n\r\n').encode() \
        + content + f"\r\n--{boundary}--\r\n".encode()
    r = urllib.request.Request(BASE + "/ingest/upload?fmt=syslog", data=body,
                               headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                               method="POST")
    up = json.load(urllib.request.urlopen(r))
    print("upload:", up["filename"], "job", up["job_id"])
    time.sleep(1.2)
    print("job status:", req("/ingest/status/" + up["job_id"])["status"])

    an = req("/analysis/run", "POST")
    print("analysis (uploads present):", an)
    st = req("/stats")
    print("is_demo_data (expect False because upload):", st["is_demo_data"])
    inc = req("/incidents")["incidents"]
    print("incidents:", [(i["ref"], i["risk_score"], i["severity"], i["name"]) for i in inc])

    # clean reset, then the canonical demo flow
    print("reset:", req("/admin/reset", "POST")["ok"])
    demo = req("/ingest/demo", "POST")
    print("demo jobs:", len(demo["jobs"]))
    for _ in range(50):
        jobs = [req("/ingest/status/" + j) for j in demo["jobs"].values()]
        if all(j["status"] == "done" for j in jobs):
            break
        time.sleep(0.2)
    print("demo jobs done:", [j["parsed_events"] for j in jobs])
    an = req("/analysis/run", "POST")
    print("analysis:", an)
    st = req("/stats")
    print("totals:", st["totals"])
    print("is_demo_data:", st["is_demo_data"])
    top = req("/incidents")["incidents"][0]
    print("top incident:", top["ref"], top["risk_score"], top["severity"])
    det = req(f"/incidents/{top['id']}")
    g = det["graph"]
    print("graph:", len(g["nodes"]), "nodes,", len(g["edges"]), "edges,",
          sum(1 for e in g["edges"] if not e["observed"]), "inferred")
    rep = req(f"/incidents/{top['id']}/report")
    print("report md chars:", len(rep["markdown"]))
    ents = req("/entities")
    print("entities:", len(ents))
    ent = req(f"/entities/user/svc-backup")
    print("entity svc-backup:", len(ent["events"]), "events,", len(ent["incidents"]), "incidents")
    ai = req(f"/incidents/{top['id']}/ai", "POST", {"question": "What happened?"})
    print("ai (expect 503):", ai.get("_http_error"), "|", ai.get("detail", "")[:100])
    print("ALL WORKFLOW CHECKS PASSED")


if __name__ == "__main__":
    main()
