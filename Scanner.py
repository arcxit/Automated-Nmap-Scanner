import csv, subprocess, shlex, datetime as dt
from pathlib import Path
from jinja2 import Template

def run_nmap(target):
    # basic service/version scan; adjust as needed
    cmd = f"nmap -sV {shlex.quote(target)}"
    print("Running:", cmd)
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    return out

def parse_nmap(output):
    """
    Parse lines like:
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1
    """
    rows = []
    for line in output.splitlines():
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            port = parts[0]
            state = parts[1] if len(parts) > 1 else ""
            service = parts[2] if len(parts) > 2 else ""
            rows.append({"port": port, "state": state, "service": service})
    return rows

def main():
    targets = [t.strip() for t in Path("targets.txt").read_text().splitlines() if t.strip()]
    all_rows = []
    for t in targets:
        o = run_nmap(t)
        for r in parse_nmap(o):
            r["host"] = t
            all_rows.append(r)

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = Path(f"nmap_report_{ts}.csv")
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["host","port","service","state"])
        w.writeheader()
        w.writerows(all_rows)
    print("Wrote", csv_path)

    # HTML
    tpl = Template(Path("report_template.html").read_text())
    html = tpl.render(targets=targets, results=all_rows)
    html_path = Path(f"nmap_report_{ts}.html")
    html_path.write_text(html, encoding="utf-8")
    print("Wrote", html_path)

if __name__ == "__main__":
    main()
