#!/usr/bin/env python3

import subprocess
import os
import sys
import requests
import shutil
import signal

# ====== Config ======
REQUIRED_TOOLS = [
    "seclists", "jq", "ffuf", "feroxbuster", "katana", "LinkFinder",
    "flameshot", "lsd", "subfinder", "assetfinder", "aquatone",
    "gau", "waybackurls", "OneForAll", "shodan", "Amass", "Sublist3r",
    "Assetfinder", "httpx", "GoSpider", "Subdomainizer", "CeWL", "ShuffleDNS",
    "Nuclei", "CTL", "DNSx", "Cloud Enum", "Metabigor", "Github Recon", "Naabu",
    "Censys"
]

INSTALL_DIR = "/opt"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# ====== Colors ======
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
NC = "\033[0m"

# ====== Banner ======
def show_banner():
    print_colored(r"""
__  __     __  __     __   __     ______   ______   ______     ______     __         ______    
/\ \_\ \   /\ \/\ \   /\ "-.\ \   /\__  _\ /\__  _\ /\  __ \   /\  __ \   /\ \       /\  ___\   
\ \  __ \  \ \ \_\ \  \ \ \-.  \  \/_/\ \/ \/_/\ \/ \ \ \/\ \  \ \ \/\ \  \ \ \____  \ \___  \  
 \ \_\ \_\  \ \_____\  \ \_\\"\_\    \ \_\    \ \_\  \ \_____\  \ \_____\  \ \_____\  \/\_____\ 
  \/_/\/_/   \/_____/   \/_/ \/_/     \/_/     \/_/   \/_____/   \/_____/   \/_____/   \/_____/ 

        Author: l0n3m4n | Version: v1.0.2 | Bughunting Automation Installer 
    """, BLUE)

# ====== Utilities ======
def print_colored(message, color):
    print(f"{color}{message}{NC}")

def run_cmd(cmd):
    """Run shell command and return CompletedProcess"""
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def is_root():
    return os.geteuid() == 0

def is_installed(tool):
    return shutil.which(tool) is not None

def install_with_apt(tool):
    print_colored(f"[-] Installing {tool} via APT...", YELLOW)
    result = run_cmd(f"apt install -y {tool}")
    return result.returncode == 0

def clone_github_repo(tool, repo_url):
    target_path = os.path.join(INSTALL_DIR, tool)
    if os.path.exists(target_path):
        print_colored(f"[!] {tool} already exists at {target_path}, skipping clone.\n", GREEN)
        return False

    print_colored(f"[~] Cloning {repo_url} into {target_path}...", YELLOW)
    result = run_cmd(f"git clone {repo_url} {target_path}")
    if result.returncode == 0:
        print_colored(f"[✓] Cloned {tool} to {target_path}.\n", GREEN)
        return True
    else:
        print_colored(f"[✗] Failed to clone {tool} from GitHub.\n", RED)
        return False

def search_github_repo(tool):
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    url = f"https://api.github.com/search/repositories?q={tool}+in:name&sort=stars&order=desc"

    print_colored(f"[~] Searching GitHub for {tool}...", YELLOW)
    try:
        response = requests.get(url, headers=headers)
        data = response.json()

        if "message" in data and "API rate limit" in data["message"]:
            print_colored("[✗] GitHub API rate limit exceeded. Set GITHUB_TOKEN.", RED)
            return None

        repo_url = None
        for item in data.get("items", []):
            if tool.lower() in item["name"].lower():
                repo_url = item["clone_url"]
                break

        # Fallback: first result if no exact match
        if not repo_url and data.get("items"):
            repo_url = data["items"][0]["clone_url"]

        return repo_url
    except Exception as e:
        print_colored(f"[✗] GitHub API error: {e}", RED)
        return None

def handle_tool_installation(tool):
    """Check and install a tool via APT or GitHub fallback."""
    if is_installed(tool):
        print_colored(f"[+] {tool} is already installed.\n", GREEN)
        return "installed"

    if install_with_apt(tool):
        print_colored(f"[✓] {tool} installed via APT.\n", GREEN)
        return "installed"

    # APT failed — try GitHub
    install_path = os.path.join(INSTALL_DIR, tool)
    if os.path.exists(install_path):
        print_colored(f"[!] {tool} already exists at {install_path}, skipping GitHub clone.\n", GREEN)
        return "installed"

    repo_url = search_github_repo(tool)
    if repo_url:
        if clone_github_repo(tool, repo_url):
            return "manual"
        else:
            print_colored(f"[✗] Failed to clone {tool}.\n", RED)
            return "failed"
    else:
        print_colored(f"[✗] No repo found for {tool}. Skipping.\n", RED)
        return "failed"

# ====== Handle user interruption (Ctrl+C or Ctrl+Z) ======
def signal_handler(sig, frame):
    if sig == signal.SIGINT:
        print_colored("\n[!] Script interrupted by user (Ctrl+C). Exiting...", RED)
    elif sig == signal.SIGTSTP:
        print_colored("\n[!] Script suspended by user (Ctrl+Z). Exiting...", RED)
    sys.exit(1)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTSTP, signal_handler)

def main():
    if not is_root():
        print_colored("[!] Please run this script as root (use sudo).", RED)
        sys.exit(1)

    show_banner()

    print_colored("[*] Starting tool installation process...\n", BLUE)
    run_cmd("apt update -y")

    installed_count = 0
    manual_count = 0
    failed_count = 0
    total = len(REQUIRED_TOOLS)

    for idx, tool in enumerate(REQUIRED_TOOLS, start=1):
        percent = int((idx / total) * 100)
        print_colored(f"[{percent}%] Checking {tool} ({idx}/{total})", YELLOW)

        result = handle_tool_installation(tool)
        if result == "installed":
            installed_count += 1
        elif result == "manual":
            manual_count += 1
        elif result == "failed":
            failed_count += 1

    print_colored(f"\nSummary:", BLUE)
    print_colored(f"  Installed via APT or already present: {installed_count}", GREEN)
    print_colored(f"  Installed manually from GitHub: {manual_count}", YELLOW)
    print_colored(f"  Failed to install: {failed_count}\n", RED)

    print_colored("[✓] All tools checked and processed.\n", BLUE)
    print_colored(f"Summary: {installed_count} tool(s) installed via APT or already present.", GREEN)
    print_colored(f"         {manual_count} tool(s) cloned from GitHub.", YELLOW)

if __name__ == "__main__":
    main()
