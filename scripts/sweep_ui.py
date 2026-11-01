"""Final sweep: unresolved JS calls + CSS class coverage."""
import io
import re

js = io.open("frontend/assets/app.js", encoding="utf-8").read()
gjs = io.open("frontend/assets/graph.js", encoding="utf-8").read()
css = io.open("frontend/assets/style.css", encoding="utf-8").read()

defined = set(re.findall(r"function\s+(\w+)\s*\(", js))
defined |= set(re.findall(r"function\s+(\w+)\s*\(", gjs))
defined.add("KillGraph")

builtin = {"fetch", "setTimeout", "clearTimeout", "setInterval", "clearInterval",
           "encodeURIComponent", "decodeURIComponent", "JSON", "Math", "Date", "Number",
           "String", "Object", "Array", "Set", "Map", "Blob", "URL", "FormData",
           "document", "window", "location", "requestAnimationFrame",
           "cancelAnimationFrame", "parseInt", "parseFloat", "isNaN", "console",
           "Error", "Promise", "alert"}

calls = set(re.findall(r"(?<![.\w'\"])([a-zA-Z_]\w{2,})\s*\(", js))
missing = sorted(c for c in calls if c not in defined and c not in builtin)
print("unresolved JS calls:", missing if missing else "NONE")

# CSS classes used in app.js templates (skip dynamic ${} pieces)
classes = set()
for m in re.finditer(r'class="([^"]+)"', js):
    for c in m.group(1).split():
        if "${" in c:
            c = c.split("${")[0]
        c = c.strip('"')
        if c:
            classes.add(c)
missing_css = []
for c in sorted(classes):
    if c.startswith(("sev-", "c-")):
        continue
    if ("." + c) not in css:
        missing_css.append(c)
print("css classes missing:", missing_css if missing_css else "NONE")
