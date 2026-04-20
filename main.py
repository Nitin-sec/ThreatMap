"""
main.py — ThreatMap Infra v1.0
Correct UX flow:
  1. Banner
  2. Target
  3. Legal disclaimer
  4. Mode + subdomain options
  5. SCAN (progress bar)
  6. Summary table
  7. Ask format + where to save
  8. Generate report
  9. Auto-open HTML + menu
"""

import contextlib, io, logging, os, shutil, platform, subprocess, sys, threading, warnings
from datetime import datetime
from pathlib import Path

warnings.filterwarnings("ignore")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
logging.getLogger("huggingface_hub").setLevel(logging.CRITICAL)
logging.getLogger("llama_cpp").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.ERROR)

import questionary
from rich.console import Console
from rich.table import Table
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from rich import box

from scanner_core       import Target, ScannerKit, ParallelOrchestrator, MODE_BALANCED, MODE_AGGRESSIVE
from report_parser      import ThreatMapParser
from db_manager         import DBManager
from evidence_collector import EvidenceCollector
from report_generator   import generate_report
from ai_triage          import run_ai_triage
from authorization_gate import AuthorizationGate

console = Console()

SEV_COLOR = {"Critical":"red","High":"orange1","Medium":"yellow","Low":"green","Info":"bright_blue"}
SEV_SLA   = {"Critical":"Patch within 24h","High":"Patch within 7 days",
             "Medium":"Fix within 30 days","Low":"Quarterly review","Info":"Informational"}
SEV_ORDER = ["Critical","High","Medium","Low","Info"]

Q = questionary.Style([
    ("qmark","fg:red bold"),("question","fg:white bold"),("answer","fg:cyan bold"),
    ("pointer","fg:red bold"),("highlighted","fg:cyan bold"),("selected","fg:cyan"),
    ("instruction","fg:gray"),
])


def _configure_logging(log_path):
    root = logging.getLogger("threatmap")
    root.setLevel(logging.DEBUG); root.handlers.clear()
    fh = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-8s  %(name)s  %(message)s", datefmt="%H:%M:%S"))
    root.addHandler(fh); root.propagate = False

def _i(msg):  console.print(f"  [bold blue][[*]][/bold blue]  {msg}")
def _ok(msg): console.print(f"  [bold green][[+]][/bold green]  {msg}")
def _w(msg):  console.print(f"  [bold yellow][[!]][/bold yellow]  {msg}")
def _e(msg):  console.print(f"  [bold red][[-]][/bold red]  {msg}")

def ensure_workdir():
    if os.path.exists("reports"): shutil.rmtree("reports")
    os.makedirs("reports")

def open_report(path):
    if not path or not os.path.isfile(path):
        _w(f"File not found: {path}"); return False
    for app in (["firefox","chromium","chromium-browser","xdg-open"] if path.endswith(".html")
                else ["libreoffice","gnumeric","xdg-open"]):
        if shutil.which(app):
            subprocess.Popen([app, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
    _w(f"Open manually: {path}"); return False


def _banner():
    console.print()
    for line in [
        "  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███╗   ███╗ █████╗ ██████╗  ",
        "     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗ ",
        "     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██╔████╔██║███████║██████╔╝  ",
        "     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║╚██╔╝██║██╔══██║██╔═══╝   ",
        "     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ██║ ╚═╝ ██║██║  ██║██║        ",
        "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝       ",
    ]:
        console.print(f"[bold red]{line}[/bold red]")
    console.print()
    info = Table.grid(padding=(0,4))
    info.add_column(min_width=12); info.add_column()
    info.add_row("[dim]Version[/dim]",   "[white]1.0[/white]  [dim]·  VAPT + EASM Scanner[/dim]")
    info.add_row("[dim]Platform[/dim]",  "[white]Kali Linux[/white]  [dim]·  Authorized use only[/dim]")
    info.add_row("[dim]Storage[/dim]",   "[white]100% Local[/white]  [dim]·  No data leaves your machine[/dim]")
    info.add_row("[dim]AI Triage[/dim]", "[white]SLM / Groq / Rule-based[/white]")
    console.print(info); console.print()
    console.print(Rule(style="dim red")); console.print()


def _show_summary(triage_rows, host_id_map):
    console.print()
    console.print(Rule("[dim]Scan Results[/dim]", style="dim green"))
    console.print()
    if not triage_rows:
        _w("No open ports or findings detected.")
        _i("Tip: try [bold]scanme.nmap.org[/bold] as a safe public test target")
        return False

    sev_counts = {}
    for r in triage_rows:
        sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim", pad_edge=False, show_edge=False)
    t.add_column("  Severity", min_width=12, style="bold")
    t.add_column("  Count",    min_width=7,  justify="right")
    t.add_column("  SLA",      min_width=26, style="dim")
    for sev in SEV_ORDER:
        cnt = sev_counts.get(sev, 0)
        if cnt > 0:
            col = SEV_COLOR.get(sev, "white")
            t.add_row(f"  [{col}]{sev}[/{col}]", f"  [{col}]{cnt}[/{col}]", f"  {SEV_SLA.get(sev,'')}")
    t.add_section()
    t.add_row("  [dim]Hosts[/dim]", f"  [white]{len(host_id_map)}[/white]", "")
    ai_n = sum(1 for r in triage_rows if r["ai_enhanced"])
    t.add_row("  [dim]Findings[/dim]", f"  [white]{len(triage_rows)}[/white]", f"  [dim]{ai_n} AI-enhanced[/dim]")
    console.print(t); console.print()
    return True


def _ask_output():
    """Ask format + save location AFTER scan is done."""
    console.print(Rule("[dim]Save Report[/dim]", style="dim blue"))
    console.print()

    fmt_raw = questionary.select(
        "  Select report format:",
        choices=[
            "HTML   — Recommended. Opens in any browser, zero dependencies.",
            "Excel  — Requires LibreOffice or MS Office.",
            "Both   — HTML and Excel.",
        ],
        style=Q,
    ).ask()
    if not fmt_raw:
        return str(Path.home() / "ThreatMap-Reports"), "html"
    fmt = "html" if "HTML" in fmt_raw else "excel" if "Excel" in fmt_raw else "both"
    console.print()

    default_save = str(Path.home() / "ThreatMap-Reports")
    save_raw = questionary.text(
        "  Save to folder:",
        default=default_save,
        instruction="(press Enter for default)",
        style=Q,
    ).ask()
    save_dir = (save_raw or default_save).strip()
    try:
        Path(save_dir).mkdir(parents=True, exist_ok=True)
        _ok(f"Saving to: [cyan]{save_dir}[/cyan]")
    except Exception as exc:
        _w(f"Cannot use that folder ({exc}) — using default.")
        save_dir = default_save
        Path(save_dir).mkdir(parents=True, exist_ok=True)
    console.print()
    return save_dir, fmt


def _menu(reports, log_path):
    html_path  = reports.get("html_path")
    excel_path = reports.get("excel_path")

    console.print(Rule("[dim]Your Reports[/dim]", style="dim"))
    console.print()
    if html_path:  _ok(f"HTML  →  [cyan]{html_path}[/cyan]")
    if excel_path: _ok(f"Excel →  [cyan]{excel_path}[/cyan]")
    _ok(f"Log   →  [cyan]{log_path}[/cyan]")
    console.print()

    # Auto-open HTML immediately
    if html_path:
        _i("Opening HTML report in browser...")
        open_report(html_path)
        console.print()

    choices = []
    if html_path:  choices.append("Open HTML Report again")
    if excel_path: choices.append("Open Excel Report")
    choices.append("Open Scan Log")
    choices.append("Exit")

    console.print(Rule("[dim]Actions[/dim]", style="dim"))
    console.print()

    while True:
        choice = questionary.select("  Select action:", choices=choices, style=Q).ask()
        if not choice or "Exit" in choice:
            console.print(); _ok("Session complete."); console.print(); break
        elif "HTML" in choice:
            open_report(html_path); _i("Opened.")
        elif "Excel" in choice:
            open_report(excel_path); _i("Opened.")
        elif "Log" in choice:
            open_report(log_path); _i("Opened.")


def main():
    _banner()

    # 1. Target
    target_input = questionary.text(
        "  tm> ? target:",
        validate=lambda v: True if v.strip() else "Target cannot be empty.",
        style=Q,
    ).ask()
    if not target_input: return
    console.print()

    # 2. Authorization
    if not AuthorizationGate().validate(target_input.strip()):
        _e("Scan aborted."); return
    console.print()

    # 3. Mode
    mode_raw = questionary.select(
        "  tm> ? scan mode:",
        choices=[
            "balanced   — Recommended. Fast, focused, low noise.",
            "aggressive — All 65,535 ports + full Nuclei. Loud.",
        ],
        style=Q,
    ).ask()
    if not mode_raw: return
    mode = MODE_AGGRESSIVE if "aggressive" in mode_raw else MODE_BALANCED

    if mode == MODE_AGGRESSIVE:
        console.print()
        if not questionary.confirm("  Aggressive scans all 65,535 ports. Confirm?", default=False, style=Q).ask():
            _w("Switching to balanced mode."); mode = MODE_BALANCED
    console.print()

    # 4. Subdomain sweep
    full_scan = questionary.confirm("  tm> ? enumerate subdomains?", default=False, style=Q).ask()
    console.print()

    # 5. Setup
    ensure_workdir()
    log_path = "reports/scan.log"
    _configure_logging(log_path)

    target      = Target(target_input.strip())
    db          = DBManager()
    scan_id     = db.init_scan(target=target.domain, scan_mode=mode, max_workers=4)
    parser      = ThreatMapParser(target.domain)
    live_hosts  = []
    host_id_map = {}

    _i(f"Scanning [bold white]{target.domain}[/bold white]  [dim]({('Balanced' if mode==MODE_BALANCED else 'Aggressive')})[/dim]")
    console.print()

    # 6. SCAN
    with Progress(
        TextColumn("  [bold blue][[*]][/bold blue]  [progress.description]{task.description:<28}"),
        SpinnerColumn(spinner_name="dots", style="red"),
        BarColumn(bar_width=22, complete_style="red", finished_style="green"),
        TaskProgressColumn(), TimeElapsedColumn(),
        console=console, transient=False,
    ) as progress:

        disc = progress.add_task("Discovery", total=3)
        if full_scan:
            subs = list(set(ScannerKit.run_subfinder(target) + ScannerKit.run_assetfinder(target)))
            progress.advance(disc); progress.advance(disc)
            if subs: Path("reports/subdomains.txt").write_text("\n".join(subs))
            live_hosts = ScannerKit.run_httpx() or [target.url]
            progress.advance(disc)
        else:
            live_hosts = [target.url]
            progress.update(disc, completed=3)

        task_scan = progress.add_task("Scanning hosts", total=len(live_hosts))
        orchestrator = ParallelOrchestrator(mode=mode)
        scan_results = {}
        lock = threading.Lock()

        def _scan_one(host):
            r = orchestrator._scan_single_host(host)
            with lock: scan_results[host] = r
            progress.advance(task_scan)

        threads = [threading.Thread(target=_scan_one, args=(h,), daemon=True) for h in live_hosts]
        for t in threads: t.start()
        for t in threads: t.join()

        task_db = progress.add_task("Saving results", total=max(len(scan_results),1))
        for host, result in scan_results.items():
            if result.get("error"): progress.advance(task_db); continue
            ht = Target(host)
            hid = db.upsert_host(scan_id, host, ht.domain)
            host_id_map[host] = hid
            if result.get("nmap"): db.insert_ports(hid, result["nmap"])
            parser.parse_host_reports(host)
            progress.advance(task_db)

        http_hosts = [h for h in host_id_map if h.startswith("http")]
        task_ev = progress.add_task("Evidence collection", total=max(len(http_hosts),1))
        if http_hosts:
            EvidenceCollector().probe_hosts(hosts=http_hosts, output_dir="reports")
        progress.update(task_ev, completed=max(len(http_hosts),1))

        task_ai = progress.add_task("AI Triage", total=1)
        with contextlib.redirect_stderr(io.StringIO()):
            run_ai_triage(db=db, scan_id=scan_id)
        progress.advance(task_ai)

        parser.save_and_cleanup()
        db.complete_scan(scan_id)

    # 7. Summary
    triage_rows = db.get_all_triage()
    has_findings = _show_summary(triage_rows, host_id_map)

    if not has_findings:
        _i(f"Scan log saved: [cyan]{log_path}[/cyan]")
        return

    ai_n = sum(1 for r in triage_rows if r["ai_enhanced"])
    if ai_n > 0:
        _ok(f"AI enhanced [bold]{ai_n}[/bold] of {len(triage_rows)} findings")
    else:
        _w("AI used rule-based fallback — add a Groq key for AI analysis")
    console.print()

    # 8. Ask where to save
    save_dir, fmt = _ask_output()

    # 9. Generate
    _i("Generating report...")
    reports = generate_report(db, output_dir=save_dir, fmt=fmt)
    if not reports.get("html_path") and not reports.get("excel_path"):
        _e("Report generation failed. See scan.log."); return

    # 10. Open + menu
    _menu(reports, log_path)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print()
        console.print("  [yellow][[!]][/yellow]  Interrupted.")
        if os.path.exists("reports"): shutil.rmtree("reports")
        sys.exit(0)
