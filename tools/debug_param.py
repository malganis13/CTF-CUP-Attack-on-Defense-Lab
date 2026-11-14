import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from adkit.audit import attach_endpoint, guess_param_detail
from adkit import patterns

for rel in ("sim/vulnbox/warehouse/index.php", "sim/vulnbox/archive/server.js"):
    text = pathlib.Path(rel).read_text(encoding="utf-8")
    lines = text.splitlines()
    endpoints = sorted(patterns.map_endpoints(rel, text), key=lambda item: item["line"])
    print("==", rel)
    print("endpoints:", [item["path"] for item in endpoints])
    for finding in patterns.scan_text(rel, text):
        detail = guess_param_detail(lines, finding["line"] - 1)
        endpoint = attach_endpoint(endpoints, lines, detail[1], finding["line"] - 1) if detail else "-"
        print(f"{finding['line']:4} {finding['rule']:22} param={detail} endpoint={endpoint}")
