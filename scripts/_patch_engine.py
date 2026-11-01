"""Replace the streaming section of engine.py with cluster-based incident assembly."""
import io

path = "backend/app/analysis/engine.py"
with io.open(path, "r", encoding="utf-8") as f:
    src = f.read()

with io.open("scripts/_new_streaming.py", "r", encoding="utf-8") as f:
    new_section = f.read()

start = src.index("# ---------------------------------------------------------------------------\n# Streaming path (large datasets)")
end = src.index("def _campaign_clusters(")
src = src[:start] + new_section + "\n\n" + src[end:]

with io.open(path, "w", encoding="utf-8", newline="\n") as f:
    f.write(src)
print("engine streaming section replaced, size:", len(src))
