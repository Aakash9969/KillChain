import sqlite3

conn = sqlite3.connect("data/killchain.db", timeout=30)
conn.row_factory = sqlite3.Row
print("== sample auth_success rows ==")
for r in conn.execute("SELECT id, event_type, severity, outcome, username, action, "
                      "substr(raw,1,160) r FROM events WHERE event_type='auth_success' LIMIT 3"):
    print(tuple(r))
    print()
print("== breakdown by action/outcome ==")
for r in conn.execute("SELECT event_type, action, outcome, COUNT(*) c FROM events "
                      "GROUP BY event_type, action, outcome ORDER BY c DESC LIMIT 15"):
    print(tuple(r))
