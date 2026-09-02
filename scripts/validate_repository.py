from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
readme = (ROOT / "README.md").read_text(encoding="utf-8")
report = (ROOT / "incident_report.md").read_text(encoding="utf-8")
events = (ROOT / "windows_security.log").read_text(encoding="utf-8")

for required in ("EventCode=4625", "T1110.001", "stats count", "where count >= 3"):
    assert required in readme, f"README is missing required detection evidence: {required}"

for required in ("administrator", "192.168.1.105"):
    assert required in report, f"Incident report is missing: {required}"

failed_logons = len(re.findall(r"EventCode[=:]4625", events, flags=re.IGNORECASE))
assert failed_logons >= 5, f"Expected at least five failed-logon events, found {failed_logons}"
assert (ROOT / "screenshot_splunk_brute_force.png").exists(), "Evidence screenshot is missing"

print(f"Validated documentation, screenshot and {failed_logons} failed-logon events.")
