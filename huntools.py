#!/usr/bin/env python3

import os
import sys
import re
import subprocess
import argparse
import shutil
import platform
import yaml
import hashlib
import textwrap
import urllib.request



class Colors:
    # Reset
    NC = '\033[0m' 

    # Text Styles
    BOLD = '\033[1m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    INVERSE = '\033[7m' 
    STRIKETHROUGH = '\033[9m'

    # Foreground Colors
    BLACK = '\033[0;30m'
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[0;37m'

    # Bright Foreground Colors
    BRIGHT_BLACK = '\033[0;90m'
    BRIGHT_RED = '\033[0;91m'
    BRIGHT_GREEN = '\033[0;92m'
    BRIGHT_YELLOW = '\033[0;93m'
    BRIGHT_BLUE = '\033[0;94m'
    BRIGHT_MAGENTA = '\033[0;95m'
    BRIGHT_CYAN = '\033[0;96m'
    BRIGHT_WHITE = '\033[0;97m'

    # Bold Foreground Colors (expanding)
    BOLD_BLACK = '\033[1;30m'
    BOLD_RED = '\033[1;31m'
    BOLD_GREEN = '\033[1;32m'
    BOLD_YELLOW = '\033[1;33m'
    BOLD_BLUE = '\033[1;34m'
    BOLD_MAGENTA = '\033[1;35m'
    BOLD_CYAN = '\033[1;36m'
    BOLD_WHITE = '\033[1;37m'

    # Background Colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # Bright Background Colors
    BG_BRIGHT_BLACK = '\033[100m'
    BG_BRIGHT_RED = '\033[101m'
    BG_BRIGHT_GREEN = '\033[102m'
    BG_BRIGHT_YELLOW = '\033[103m'
    BG_BRIGHT_BLUE = '\033[104m'
    BG_BRIGHT_MAGENTA = '\033[105m'
    BG_BRIGHT_CYAN = '\033[106m'
    BG_BRIGHT_WHITE = '\033[107m'

def _log_error(message):
    clean_message = re.sub(r'\x1b\[([0-9]{1,2};)?([0-9]{1,2})?m', '', message)
    with open("detailed_errors.log", "a") as f:
        f.write(clean_message + "\n")


def show_banner():
    tool_count = len(ALL_TOOLS)
    banner = f'''  
 ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓ ▒█████   ▒█████   ██▓      ██████ 
▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    ▒██    ▒ 
▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    ░ ▓██▄   
░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░      ▒   ██▒
░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒▒██████▒▒
 ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░▒ ▒▓▒ ▒ ░
 ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░░ ░▒  ░ ░
 ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   ░  ░  ░  
 ░  ░  ░   ░              ░              ░ ░      ░ ░      ░  ░      ░  
                                                                        
           Author: l0n3m4n | Version: 3.3.0 | {tool_count} Hunter Tools
\n'''
    print(f"{Colors.CYAN}{banner}{Colors.NC}", end="")




# Master Tool List: You can add more tools here as needed, and you can delete tools you don't want to install
ALL_TOOLS = {
    
    # Go Tools
    "ffuf": {"type": "go", "install": "go install -v github.com/ffuf/ffuf/v2@latest"},
    "feroxbuster": {"type": "go", "install": "go install -v github.com/epi052/feroxbuster@latest"},
    "katana": {"type": "go", "install": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"},
    "subfinder": {"type": "go", "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "assetfinder": {"type": "go", "install": "go install -v github.com/tomnomnom/assetfinder@latest"},
    #"aquatone": {"type": "go", "install": "go install -v github.com/michenriksen/aquatone@latest"},
    "gau": {"type": "go", "install": "go install -v github.com/lc/gau/v2/cmd/gau@latest"},
    "waybackurls": {"type": "go", "install": "go install -v github.com/tomnomnom/waybackurls@latest"},
    "Amass": {"type": "go", "install": "go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest"},
    "httpx": {"type": "go", "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "GoSpider": {"type": "go", "install": "go install -v github.com/jaeles-project/gospider@latest"},
    "ShuffleDNS": {"type": "go", "install": "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"},
    "Nuclei": {"type": "go", "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "DNSx": {"type": "go", "install": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
    "Naabu": {"type": "go", "install": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
    "ct-exposer": {"type": "go", "install": "go get -u github.com/crt.sh/ct-exposer"},
    "metabigor": {"type": "go", "install": "go install -v github.com/j3ssie/metabigor@latest"},
    "gf": {"type": "go", "install": "go install -v github.com/tomnomnom/gf@latest"},
    "brutespray": {"type": "go", "install": "go install -v github.com/x90skysn3k/brutespray@latest"},
    "qsreplace": {"type": "go", "install": "go install -v github.com/tomnomnom/qsreplace@latest"},
    "github-subdomains": {"type": "go", "install": "go install -v github.com/gwen001/github-subdomains@latest"},
    "gitlab-subdomains": {"type": "go", "install": "go install -v github.com/gwen001/gitlab-subdomains@latest"},
    "anew": {"type": "go", "install": "go install -v github.com/tomnomnom/anew@latest"},
    "notify": {"type": "go", "install": "go install -v github.com/projectdiscovery/notify/cmd/notify@latest"},
    "unfurl": {"type": "go", "install": "go install -v github.com/tomnomnom/unfurl@v0.3.0"},
    "github-endpoints": {"type": "go", "install": "go install -v github.com/gwen001/github-endpoints@latest"},
    "subjs": {"type": "go", "install": "go install -v github.com/lc/subjs@latest"},
    "Gxss": {"type": "go", "install": "go install -v github.com/KathanP19/Gxss@latest"},
    "crlfuzz": {"type": "go", "install": "go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"},
    "dalfox": {"type": "go", "install": "go install -v github.com/hahwul/dalfox/v2@latest"},
    "puredns": {"type": "go", "install": "go install -v github.com/d3mondev/puredns/v2@latest"},
    "interactsh-client": {"type": "go", "install": "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"},
    "analyticsrelationships": {"type": "go", "install": "go install -v github.com/Josue87/analyticsrelationships@latest"},
    "gotator": {"type": "go", "install": "go install -v github.com/Josue87/gotator@latest"},
    "roboxtractor": {"type": "go", "install": "go install -v github.com/Josue87/roboxtractor@latest"},
    "mapcidr": {"type": "go", "install": "go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"},
    "cdncheck": {"type": "go", "install": "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"},
    "dnstake": {"type": "go", "install": "go install -v github.com/pwnesia/dnstake/cmd/dnstake@latest"},
    "tlsx": {"type": "go", "install": "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
    "gitdorks_go": {"type": "go", "install": "go install -v github.com/damit5/gitdorks_go@latest"},
    "smap": {"type": "go", "install": "go install -v github.com/s0md3v/smap/cmd/smap@latest"},
    "dsieve": {"type": "go", "install": "go install -v github.com/trickest/dsieve@master"},
    "inscope": {"type": "go", "install": "go install -v github.com/tomnomnom/hacks/inscope@latest"},
    "enumerepo": {"type": "go", "install": "go install -v github.com/trickest/enumerepo@latest"},
    "Web-Cache-Vulnerability-Scanner": {"type": "go", "install": "go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest"},
    "hakip2host": {"type": "go", "install": "go install -v github.com/hakluke/hakip2host@latest"},
    "mantra": {"type": "go", "install": "go install -v github.com/Brosck/mantra@latest"},
    "crt": {"type": "go", "install": "go install -v github.com/cemulus/crt@latest"},
    "s3scanner": {"type": "go", "install": "go install -v github.com/sa7mon/s3scanner@latest"},
    "nmapurls": {"type": "go", "install": "go install -v github.com/sdcampbell/nmapurls@latest"},
    "shortscan": {"type": "go", "install": "go install -v github.com/bitquark/shortscan/cmd/shortscan@latest"},
    "sns": {"type": "go", "install": "go install github.com/sw33tLie/sns@latest"},
    "ppmap": {"type": "go", "install": "go install -v github.com/kleiton0x00/ppmap@latest"},
    "sourcemapper": {"type": "go", "install": "go install -v github.com/denandz/sourcemapper@latest"},
    "jsluice": {"type": "go", "install": "go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest"},
    "urlfinder": {"type": "go", "install": "go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"},
    "cent": {"type": "go", "install": "go install -v github.com/xm1k3/cent@latest"},
    "csprecon": {"type": "go", "install": "go install github.com/edoardottt/csprecon/cmd/csprecon@latest"},
    "VhostFinder": {"type": "go", "install": "go install -v github.com/wdahlenburg/VhostFinder@latest"},
    "misconfig-mapper": {"type": "go", "install": "go install github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper@latest"},
    "gitleaks": {"type": "go", "install": "git clone https://github.com/gitleaks/gitleaks.git /tmp/gitleaks_build && cd /tmp/gitleaks_build && make build && mv ./gitleaks \"$GOBIN\" && rm -rf /tmp/gitleaks_build"},
    "trufflehog": {"type": "go", "install": "go install -v github.com/trufflesecurity/trufflehog/v3@latest"},

    # Package Tools
    "seclists": {"type": "package"},
    "jq": {"type": "package"},
    "flameshot": {"type": "package"},
    "lsd": {"type": "package"},
    "cewl": {"type": "package"},
    "nmap": {"type": "package"},
    "massdns": {"type": "package"},

    # Python Git Tools
    "LinkFinder": {"type": "python_git", "url": "https://github.com/GerbenJavado/LinkFinder.git"},
    "OneForAll": {"type": "python_git", "url": "https://github.com/shmilylty/OneForAll.git"},
    "cloud_enum": {"type": "python_git", "url": "https://github.com/initstring/cloud_enum.git"},
    "dorks_hunter": {"type": "python_git", "url": "https://github.com/six2dez/dorks_hunter.git"},
    "Corsy": {"type": "python_git", "url": "https://github.com/s0md3v/Corsy.git"},
    "CMSeeK": {"type": "python_git", "url": "https://github.com/Tuhinshubhra/CMSeeK.git"},
    "fav-up": {"type": "python_git", "url": "https://github.com/pielco11/fav-up.git"},
    "Oralyzer": {"type": "python_git", "url": "https://github.com/r0075h3ll/Oralyzer.git"},
    "JSA": {"type": "python_git", "url": "https://github.com/w9w/JSA.git"},
    "CloudHunter": {"type": "python_git", "url": "https://github.com/belane/CloudHunter.git"},
    "pydictor": {"type": "python_git", "url": "https://github.com/LandGrey/pydictor.git"},
    "smuggler": {"type": "python_git", "url": "https://github.com/defparam/smuggler.git"},
    "regulator": {"type": "python_git", "url": "https://github.com/cramppet/regulator.git"},
    "nomore403": {"type": "python_git", "url": "https://github.com/devploit/nomore403.git"},
    "SwaggerSpy": {"type": "python_git", "url": "https://github.com/UndeadSec/SwaggerSpy.git"},
    "LeakSearch": {"type": "python_git", "url": "https://github.com/JoelGMSec/LeakSearch.git"},
    "Spoofy": {"type": "python_git", "url": "https://github.com/MattKeeley/Spoofy.git"},
    "msftrecon": {"type": "python_git", "url": "https://github.com/Arcanum-Sec/msftrecon.git"},
    "Scopify": {"type": "python_git", "url": "https://github.com/Arcanum-Sec/Scopify.git"},
    "metagoofil": {"type": "python_git", "url": "https://github.com/opsdisk/metagoofil.git"},
   
    # Python Pip Tools
    "censys": {"type": "pip"},
    "shodan": {"type": "pip"},
    #"dnsvalidator": {"type": "pip"},
    #"interlace": {"type": "pip"},
    "wafw00f": {"type": "pip"},
    "commix": {"type": "pip"},
    "urless": {"type": "pip"},
    #"ghauri": {"type": "pip"},
    "xnLinkFinder": {"type": "pip"},
    #"xnldorker": {"type": "pip"},
    "porch-pirate": {"type": "pip"},
    "p1radup": {"type": "pip"},
    #"subwiz": {"type": "pip"},

    # Git Repos
    "Gf-Patterns": {"type": "git", "url": "https://github.com/1ndianl33t/Gf-Patterns.git"},
    "sus_params": {"type": "git", "url": "https://github.com/g0ldencybersec/sus_params.git"},
}


ALL_TOOLS_LOWER_MAP = {name.lower(): name for name in ALL_TOOLS.keys()}
CONFIG_DIR = os.path.join(os.environ["HOME"], ".config", "huntools")

DEFAULT_HUNTOOLS_INSTALL_DIR = os.path.join(os.environ["HOME"], ".huntools")
DEFAULT_GO_WORKSPACE_DIR = os.path.join(os.environ["HOME"], "go")
DEFAULT_GO_BIN_DIR = os.path.join(DEFAULT_GO_WORKSPACE_DIR, "bin")
DEFAULT_PYTHON_INSTALL_DIR = os.path.join(DEFAULT_HUNTOOLS_INSTALL_DIR, "python")
DEFAULT_GIT_INSTALL_DIR = os.path.join(DEFAULT_HUNTOOLS_INSTALL_DIR, "git")
config = {}

def _get_actual_config_file_path():
    default_config_file = os.path.join(CONFIG_DIR, "config.yml")
    if os.path.exists(default_config_file):
        with open(default_config_file, 'r') as f:
            try:
                temp_config = yaml.safe_load(f)
                if 'PATHS' in temp_config and 'config_file' in temp_config['PATHS']:
                    return temp_config['PATHS']['config_file']
            except yaml.YAMLError:
                pass  # Handle invalid YAML
    return default_config_file

def load_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    actual_config_file = _get_actual_config_file_path()
    global config
    try:
        with open(actual_config_file, 'r') as f:
            config = yaml.safe_load(f)
        if config is None:
            config = {}
    except FileNotFoundError:
        config = {}

    if "PATHS" not in config:
        config["PATHS"] = {
            "install_dir": DEFAULT_HUNTOOLS_INSTALL_DIR,
            "go_bin_dir": DEFAULT_GO_BIN_DIR,
            "python_dir": DEFAULT_PYTHON_INSTALL_DIR,
            "git_dir": DEFAULT_GIT_INSTALL_DIR,
            "config_file": actual_config_file # Store the current config file path
        }
        save_config() # Ensure default config is written if not exists

def save_config():
    actual_config_file = config.get("PATHS", {}).get("config_file", os.path.join(CONFIG_DIR, "config.yml"))
    os.makedirs(os.path.dirname(actual_config_file), exist_ok=True) # Ensure directory exists for custom path
    with open(actual_config_file, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

def _is_tool_installed(tool_name, tool_info):
    # Check if the tool is in the PATH
    if shutil.which(tool_name):
        return True
    
    tool_type = tool_info["type"]
    # If not in PATH, check for git repos
    if tool_type == "python_git":
        repo_path = os.path.join(config["PATHS"].get("python_dir", DEFAULT_PYTHON_INSTALL_DIR), tool_name)
        if os.path.exists(repo_path):
            return True
    elif tool_type == "git":
        repo_path = os.path.join(config["PATHS"].get("git_dir", DEFAULT_GIT_INSTALL_DIR), tool_name)
        if os.path.exists(repo_path):
            return True
    return False

def get_package_manager():
    if os.path.exists("/etc/debian_version"):
        return "apt-get"
    elif os.path.exists("/etc/redhat-release"):
        return "yum"
    elif os.path.exists("/etc/arch-release"):
        return "pacman"
    elif sys.platform == "darwin":
        return "brew"
    else:
        return None

def install_dependencies():
    print(f"{Colors.GREEN}--- 🔧 Installing system dependencies ---{Colors.NC}")
    package_manager = get_package_manager()
    if not package_manager:
        print(f"{Colors.RED}Unsupported OS. Please install dependencies manually.{Colors.NC}")
        return False

    deps = {
        "apt-get": "python3 python3-pip python3-venv git curl wget ruby nmap build-essential gcc cmake libpcap-dev dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev",
        "yum": "python3 python3-pip python3-devel git curl wget ruby nmap gcc gcc-c++ make cmake pcap-devel dnsutils openssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel",
        "pacman": "python python-pip python-virtualenv git curl wget ruby nmap base-devel gcc cmake libpcap dnsutils openssl libffi libxml2 libxslt zlib",
        "brew": "python git curl wget ruby nmap cmake"
    }

    try:
        if package_manager == "apt-get":
            print(f"{Colors.GREEN}Updating package list...{Colors.NC}")
            subprocess.run(f"sudo {package_manager} update -y", shell=True, check=True, capture_output=True)
            print(f"{Colors.GREEN}Installing dependencies...{Colors.NC}")
            try:
                subprocess.run(f"sudo {package_manager} install -y {deps[package_manager]}", shell=True, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                if "Unmet dependencies" in e.stderr.decode():
                    print(f"{Colors.YELLOW}Unmet dependencies detected. Attempting to fix with 'apt --fix-broken install'...{Colors.NC}")
                    subprocess.run(f"sudo {package_manager} --fix-broken install -y", shell=True, check=True, capture_output=True)
                    print(f"{Colors.GREEN}Retrying dependency installation...{Colors.NC}")
                    subprocess.run(f"sudo {package_manager} install -y {deps[package_manager]}", shell=True, check=True, capture_output=True)
                else:
                    raise # Re-raise if it's a different error
        elif package_manager == "yum":
            print(f"{Colors.CYAN}Installing dependencies...{Colors.NC}")
            subprocess.run(f"sudo {package_manager} install -y {deps[package_manager]}", shell=True, check=True, capture_output=True)
        elif package_manager == "pacman":
            print(f"{Colors.CYAN}Updating system...{Colors.NC}")
            subprocess.run(f"sudo {package_manager} -Syu --noconfirm", shell=True, check=True, capture_output=True)
            print(f"{Colors.CYAN}Installing dependencies...{Colors.NC}")
            subprocess.run(f"sudo {package_manager} -S --noconfirm {deps[package_manager]}", shell=True, check=True, capture_output=True)
        elif package_manager == "brew":
            print(f"{Colors.CYAN}Updating Homebrew...{Colors.NC}")
            subprocess.run(f"{package_manager} update", shell=True, check=True, capture_output=True)
            print(f"{Colors.CYAN}Installing dependencies...{Colors.NC}")
            subprocess.run(f"{package_manager} install {deps[package_manager]}", shell=True, check=True, capture_output=True)
        
        print(f"{Colors.GREEN}System dependencies installed successfully.{Colors.NC}\n")
        return True
    except subprocess.CalledProcessError as e:
        error_message = f"Error installing dependencies: {e}\nStderr: {e.stderr.decode()}"
        _log_error(error_message)
        print(f"{Colors.RED}Error installing dependencies: {e}{Colors.NC}")
        print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
        return False

def _add_go_env_to_shell_config(shell_config_path, goroot, gopath):
    if not os.path.exists(shell_config_path):
        return False

    shell_config_content = ""
    with open(shell_config_path, "r") as f:
        shell_config_content = f.read()

    go_env_vars = [
        "\n# Go environment variables added by huntools\n",
        f"export GOROOT={goroot}\n",
        f"export GOPATH={gopath}\n",
        f"export PATH=$GOPATH/bin:$GOROOT/bin:$PATH\n"
    ]

    lines_to_append = []
    for line in go_env_vars:
        if line.strip() and line.strip() not in shell_config_content:
            lines_to_append.append(line)
    
    if lines_to_append:
        with open(shell_config_path, "a") as f:
            for line in lines_to_append:
                f.write(line)
        print(f"{Colors.GREEN}Go environment variables added/updated in {shell_config_path}.{Colors.NC}")
        return True
    else:
        print(f"{Colors.YELLOW}Go environment variables already present in {shell_config_path}. No changes made.{Colors.NC}")
        return False

def install_go():
    print(f"{Colors.CYAN}--- Checking and Installing Go ---{Colors.NC}")
    if shutil.which("go"):
        print(f"{Colors.GREEN}Go is already installed.{Colors.NC}\n")
        return True

    print(f"{Colors.CYAN}Installing Go...{Colors.NC}")
    try:
        try:
            version_url = "https://go.dev/VERSION?m=text"
            version_res = subprocess.run(["curl", "-s", version_url], capture_output=True, text=True, check=True)
            version = version_res.stdout.splitlines()[0].strip()
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"{Colors.YELLOW}Could not fetch latest Go version ({e}). Falling back to a default version.{Colors.NC}")
            version = "go1.20.7"

        arch = platform.machine()
        os_name = platform.system().lower()

        if arch in ["x86_64", "amd64"]:
            arch = "amd64"
        elif arch in ["aarch64", "arm64"]:
            arch = "arm64"
        elif arch == "armv6l":
            arch = "armv6l"
        else:
            print(f"{Colors.RED}Unsupported architecture: {arch}. Please install Go manually.{Colors.NC}")
            return False

        go_url = f"https://dl.google.com/go/{version}.{os_name}-{arch}.tar.gz"
        go_tar_path = "/tmp/go.tar.gz"
        checksum_url = f"{go_url}.sha256"

        print(f"{Colors.CYAN}Downloading Go {version}...{Colors.NC}\n")
        subprocess.run(["wget", go_url, "-O", go_tar_path], check=True, capture_output=True)

        print(f"{Colors.CYAN}Verifying checksum...{Colors.NC}\n")
        try:
            checksum_res = subprocess.run(["curl", "-s", checksum_url], capture_output=True, text=True, check=True)
            expected_checksum = checksum_res.stdout.strip()
            
            sha256_hash = hashlib.sha256()
            with open(go_tar_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            calculated_checksum = sha256_hash.hexdigest()

            if expected_checksum != calculated_checksum:
                print(f"{Colors.RED}Checksum verification failed. The downloaded file may be corrupted.{Colors.NC}")
                os.remove(go_tar_path)
                return False
            print(f"{Colors.GREEN}Checksum verified successfully.{Colors.NC}\n")

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"{Colors.YELLOW}Could not verify checksum ({e}). Proceeding with installation at your own risk.{Colors.NC}\n")

        print(f"{Colors.CYAN}Installing Go...{Colors.NC}\n")
        go_install_dir = os.path.join(os.environ["HOME"], ".huntools", "go")
        os.makedirs(go_install_dir, exist_ok=True)
        
        # Remove old Go installation from the user-specific path
        subprocess.run(["rm", "-rf", go_install_dir], check=True, capture_output=True)
        
        # Extract Go into the user-specific path
        subprocess.run(["tar", "-C", go_install_dir, "-xzf", go_tar_path], check=True, capture_output=True)
        os.remove(go_tar_path)

        goroot = go_install_dir
        gopath = DEFAULT_GO_WORKSPACE_DIR
        
        print(f"{Colors.CYAN}Configuring environment variables...{Colors.NC}\n")
        
        # Update env .bashrc
        _add_go_env_to_shell_config(os.path.join(os.environ["HOME"], ".bashrc"), goroot, gopath)
        
        # Update env .zshrc
        _add_go_env_to_shell_config(os.path.join(os.environ["HOME"], ".zshrc"), goroot, gopath)

        # Update .profile 
        # Note: for systems that use it for non-login shells
        _add_go_env_to_shell_config(os.path.join(os.environ["HOME"], ".profile"), goroot, gopath)

        # Special note for fish shell users
        if "fish" in os.environ.get("SHELL", ""):
            print(f"{Colors.YELLOW}Detected fish shell. Please manually add the following to your ~/.config/fish/config.fish:{Colors.NC}")
            print(f"{Colors.YELLOW}  set -x GOROOT {goroot}{Colors.NC}")
            print(f"{Colors.YELLOW}  set -x GOPATH {gopath}{Colors.NC}")
            print(f"{Colors.YELLOW}  fish_add_path $GOPATH/bin $GOROOT/bin{Colors.NC}")
            print(f"{Colors.YELLOW}Then run 'source ~/.config/fish/config.fish' or restart your terminal.{Colors.NC}")

        print(f"{Colors.GREEN}Go has been installed successfully.{Colors.NC}")
        print(f"{Colors.YELLOW}Please restart your shell or run 'source ~/.bashrc' to apply the changes.{Colors.NC}\n")
        return True
        
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        error_message = f"Error installing Go: {e}"
        if isinstance(e, subprocess.CalledProcessError):
            error_message += f"\nStderr: {e.stderr.decode()}"
        _log_error(error_message)
        print(f"{Colors.RED}Error installing Go: {e}{Colors.NC}")
        if isinstance(e, subprocess.CalledProcessError):
            print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
        return False

def _install_tools(title, tools, install_function):
    print(f"{Colors.CYAN}--- {title} ---{Colors.NC}")
    success_count = 0
    fail_count = 0

    for tool in tools:
        existing_path = shutil.which(tool)
        if existing_path:
            print(f"{Colors.GREEN}{tool} is already installed at {Colors.MAGENTA}{existing_path}{Colors.GREEN}.{Colors.NC}")
            success_count += 1
            continue

        print(f"{Colors.CYAN}Installing {tool}...{Colors.NC}")
        try:
            install_function(tool)
            print(f"{Colors.GREEN}{tool} installed successfully.{Colors.NC}")
            success_count += 1
        except subprocess.CalledProcessError as e:
            error_message = f"Error installing {tool}: {e}\nStderr: {e.stderr.decode()}\nSuggestion: Please check the tool's repository for known issues or try manual installation. Command: {e.cmd}"
            _log_error(error_message)
            print(f"\n{Colors.RED}Error installing {tool}: {e}{Colors.NC}")
            print(f"{Colors.YELLOW}Suggestion: Please check the tool's repository for known issues or try manual installation. Command: {e.cmd}{Colors.NC}\n")
            fail_count += 1

    print(f"\n{Colors.CYAN}--- {title} summary ---{Colors.NC}")
    print(f"{Colors.GREEN}Successfully installed/skipped: {success_count}{Colors.NC}")
    print(f"{Colors.RED}Failed to install: {fail_count}{Colors.NC}\n")

    return fail_count == 0

def install_go_tools():
    go_tools = {name: tool["install"] for name, tool in ALL_TOOLS.items() if tool["type"] == "go"}
    
    def _install_go_tool(tool):
        install_command = go_tools[tool]
        subprocess.run(install_command, shell=True, check=True, capture_output=True)

    return _install_tools("Installing Go tools", go_tools.keys(), _install_go_tool)

def install_packages():
    package_tools = [name for name, tool in ALL_TOOLS.items() if tool["type"] == "package"]
    package_manager = get_package_manager()
    if not package_manager:
        print(f"{Colors.RED}Unsupported OS for package installation. Please install manually: {' '.join(package_tools)}{Colors.NC}")
        return False

    def _install_package(package):
        if package_manager == "apt-get":
            subprocess.run(f"sudo {package_manager} install -y {package}", shell=True, check=True, capture_output=True)
        elif package_manager == "yum":
            subprocess.run(f"sudo {package_manager} install -y {package}", shell=True, check=True, capture_output=True)
        elif package_manager == "pacman":
            subprocess.run(f"sudo {package_manager} -S --noconfirm {package}", shell=True, check=True, capture_output=True)
        elif package_manager == "brew":
            subprocess.run(f"{package_manager} install {package}", shell=True, check=True, capture_output=True)

    return _install_tools("Installing packages", package_tools, _install_package)

def install_python_tools():

    print(f"{Colors.CYAN}--- Installing Python tools ---{Colors.NC}")

    
    # Git tools
    python_git_tools = {name: tool["url"] for name, tool in ALL_TOOLS.items() if tool["type"] == "python_git"}
    install_dir = config["PATHS"].get("python_dir", DEFAULT_PYTHON_INSTALL_DIR)
    os.makedirs(install_dir, exist_ok=True)
    git_success_count = 0
    git_fail_count = 0

    print(f"\n{Colors.CYAN}--- Installing Python tools from Git ---{Colors.NC}")

    for tool_name, repo_url in python_git_tools.items():
        print(f"{Colors.CYAN}Installing {tool_name} from git...{Colors.NC}")
        repo_path = os.path.join(install_dir, tool_name)
        if os.path.exists(repo_path):
            if not os.path.exists(os.path.join(repo_path, ".git")):
                print(f"{Colors.YELLOW}Incomplete installation of {tool_name} found. Removing and reinstalling...{Colors.NC}")
                shutil.rmtree(repo_path)
            else:
                repo_path = os.path.join(install_dir, tool_name)
                print(f"{Colors.GREEN}{tool_name} is already installed at {Colors.MAGENTA}{repo_path}{Colors.GREEN}.{Colors.NC}")
                git_success_count += 1
                continue
        try:
            subprocess.run(["git", "clone", repo_url, repo_path], check=True, capture_output=True)
            print(f"{Colors.GREEN}{tool_name} cloned successfully.{Colors.NC}")
            git_success_count += 1

        except subprocess.CalledProcessError as e:
            error_message = f"Error installing {tool_name}: {e}\nStderr: {e.stderr.decode()}"
            _log_error(error_message)
            print(f"{Colors.RED}Error installing {tool_name}: {e}{Colors.NC}")
            print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
            git_fail_count += 1

    # Pip tools
    pip_tools = [name for name, tool in ALL_TOOLS.items() if tool["type"] == "pip"]
    def _install_pip_tool(tool):
        subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", tool], check=True, capture_output=True)
    
    print(f"\n{Colors.CYAN}--- Installing Python tools from Pip ---{Colors.NC}")
    pip_install_success = _install_tools("Installing Python tools from Pip", pip_tools, _install_pip_tool)
    
    print(f"\n{Colors.CYAN}--- Python tools installation summary ---{Colors.NC}")
    print(f"{Colors.GREEN}Successfully installed from Git: {git_success_count}{Colors.NC}")
    print(f"{Colors.RED}Failed to install from Git: {git_fail_count}{Colors.NC}")

    return git_fail_count == 0 and pip_install_success


def install_git_repos():
    print(f"{Colors.CYAN}--- Cloning other git repositories ---{Colors.NC}")
    git_repos = {name: tool["url"] for name, tool in ALL_TOOLS.items() if tool["type"] == "git"}
    install_dir = config["PATHS"].get("git_dir", DEFAULT_GIT_INSTALL_DIR)
    os.makedirs(install_dir, exist_ok=True)
    success_count = 0
    fail_count = 0

    for repo_name, repo_url in git_repos.items():
        print(f"{Colors.CYAN}Cloning {repo_name}...{Colors.NC}")
        repo_path = os.path.join(install_dir, repo_name)
        if os.path.exists(repo_path):
            if not os.path.exists(os.path.join(repo_path, ".git")):
                print(f"{Colors.YELLOW}Incomplete installation of {repo_name} found. Removing and reinstalling...{Colors.NC}")
                shutil.rmtree(repo_path)
            else:
                print(f"{Colors.GREEN}{repo_name} is already cloned.{Colors.NC}")
                success_count += 1
                continue
        try:

            subprocess.run(["git", "clone", repo_url, repo_path], check=True, capture_output=True)
            print(f"{Colors.GREEN}{repo_name} cloned successfully.{Colors.NC}")
            success_count += 1
        except subprocess.CalledProcessError as e:
            error_message = f"Error cloning {repo_name}: {e}\nStderr: {e.stderr.decode()}"
            _log_error(error_message)
            print(f"{Colors.RED}Error cloning {repo_name}: {e}{Colors.NC}")
            print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
            fail_count += 1

    print(f"\n{Colors.CYAN}--- Git repositories cloning summary ---{Colors.NC}")
    print(f"{Colors.GREEN}Successfully cloned: {success_count}{Colors.NC}")
    print(f"{Colors.RED}Failed to clone: {fail_count}{Colors.NC}\n")

    return fail_count == 0

def get_install_path():
    # Prefer /usr/local/bin, but fall back to other common paths
    common_paths = ["/usr/local/bin", "/usr/bin"]
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)

    for path in common_paths:
        if path in path_dirs and os.path.isdir(path):
            return path
    
    # If no preferred path is found, return a default
    return "/usr/local/bin"

def install_system():
    print(f"{Colors.CYAN}--- Installing huntools to the system ---{Colors.NC}")
    try:
        # Save the git repo path to the config
        git_repo_path = os.getcwd()
        config["PATHS"]["git_repo_path"] = git_repo_path
        save_config()

        huntools_path = os.path.abspath(__file__)
        install_dir = get_install_path()
        destination_path = os.path.join(install_dir, "huntools")
        
        needs_update = False
        if os.path.exists(destination_path):
            installed_mtime = os.path.getmtime(destination_path)
            local_mtime = os.path.getmtime(huntools_path)
            if local_mtime > installed_mtime:
                needs_update = True
        else:
            needs_update = True

        if needs_update:
            command = f"sudo cp {huntools_path} {destination_path} && sudo chmod +x {destination_path}"
            process = subprocess.run(command, shell=True, check=False, capture_output=True)
            if process.returncode == 0:
                print(f"{Colors.GREEN}huntools installed/updated successfully to {destination_path}.{Colors.NC}")
            else:
                print(f"{Colors.RED}Error installing/updating huntools.{Colors.NC}")
                if process.stderr:
                    print(f"{Colors.RED}Stderr: {process.stderr.decode()}{Colors.NC}")
        else:
            print(f"{Colors.GREEN}huntools is already up-to-date.{Colors.NC}")

    except Exception as e:
        print(f"{Colors.RED}An unexpected error occurred: {e}{Colors.NC}")

def install_all():
    print(f"\n{Colors.GREEN}==========================================={Colors.NC}")
    print(f"{Colors.GREEN}--- Starting Full Installation of Huntools ---{Colors.NC}")
    print(f"{Colors.GREEN}==========================================={Colors.NC}\n")

    dependencies_status = False
    go_status = False
    go_tools_status = False
    packages_status = False
    python_tools_status = False
    git_repos_status = False

    print(f"{Colors.CYAN}--- Step 1/6: Installing System Dependencies ---{Colors.NC}")
    if install_dependencies():
        dependencies_status = True
        print(f"{Colors.GREEN}--- Step 1/6: System Dependencies Installed ---{Colors.NC}\n")
    else:
        print(f"\n{Colors.RED}Installation aborted due to an error during dependency installation.{Colors.NC}")
        print(f"{Colors.RED}--- Step 1/6: System Dependencies Installation Failed ---{Colors.NC}\n")

    print(f"{Colors.CYAN}--- Step 2/6: Installing Go ---{Colors.NC}")
    if install_go():
        go_status = True
        print(f"{Colors.GREEN}--- Step 2/6: Go Installed ---{Colors.NC}\n")
    else:
        print(f"\n{Colors.RED}Installation aborted due to an error during Go installation.{Colors.NC}")
        print(f"{Colors.RED}--- Step 2/6: Go Installation Failed ---{Colors.NC}\n")

    print(f"{Colors.CYAN}--- Step 3/6: Installing Go Tools ---{Colors.NC}")
    if install_go_tools():
        go_tools_status = True
        print(f"{Colors.GREEN}--- Step 3/6: Go Tools Installation Attempted ---{Colors.NC}\n")
    else:
        print(f"\n{Colors.YELLOW}Some Go tools failed to install. Continuing with the rest of the installation...{Colors.NC}")
        print(f"{Colors.RED}--- Step 3/6: Go Tools Installation Failed ---{Colors.NC}\n")

    print(f"{Colors.CYAN}--- Step 4/6: Installing System Packages ---{Colors.NC}")
    if install_packages():
        packages_status = True
        print(f"{Colors.GREEN}--- Step 4/6: System Packages Installation Attempted ---{Colors.NC}\n")
    else:
        print(f"\n{Colors.YELLOW}Some packages failed to install. Continuing with the rest of the installation...{Colors.NC}")
        print(f"{Colors.RED}--- Step 4/6: System Packages Installation Failed ---{Colors.NC}\n")

    print(f"{Colors.CYAN}--- Step 5/6: Installing Python Tools ---{Colors.NC}")
    if install_python_tools():
        python_tools_status = True
        print(f"{Colors.GREEN}--- Step 5/6: Python Tools Installation Attempted ---{Colors.NC}\n")
    else:
        print(f"\n{Colors.YELLOW}Some Python tools failed to install. Continuing with the rest of the installation...{Colors.NC}")
        print(f"{Colors.RED}--- Step 5/6: Python Tools Installation Failed ---{Colors.NC}\n")

    print(f"{Colors.CYAN}--- Step 6/6: Cloning Git Repositories ---{Colors.NC}")
    if install_git_repos():
        git_repos_status = True
        print(f"{Colors.GREEN}--- Step 6/6: Git Repositories Cloning Attempted ---{Colors.NC}\n")
    else:
        print(f"\n{Colors.YELLOW}Some Git repositories failed to clone. Continuing with the rest of the installation...{Colors.NC}")
        print(f"{Colors.RED}--- Step 6/6: Git Repositories Cloning Failed ---{Colors.NC}\n")

    print(f"\n{Colors.GREEN}====================================={Colors.NC}")
    print(f"{Colors.GREEN}--- Huntools installation complete! ---{Colors.NC}")
    print(f"{Colors.GREEN}====================================={Colors.NC}")

    # Summary Log
    summary_log = []
    summary_log.append(f"\n{Colors.CYAN}--- Installation Summary ---{Colors.NC}")
    if dependencies_status:
        summary_log.append(f"{Colors.GREEN}System Dependencies: SUCCESS{Colors.NC}")
    else:
        summary_log.append(f"{Colors.RED}System Dependencies: FAILED (Manual intervention may be required){Colors.NC}")

    if go_status:
        summary_log.append(f"{Colors.GREEN}Go Installation: SUCCESS{Colors.NC}")
    else:
        summary_log.append(f"{Colors.RED}Go Installation: FAILED (Manual intervention may be required){Colors.NC}")

    if go_tools_status:
        summary_log.append(f"{Colors.GREEN}Go Tools: SUCCESS{Colors.NC}")
    else:
        summary_log.append(f"{Colors.YELLOW}Go Tools: PARTIAL/FAILED (Check logs for details){Colors.NC}")

    if packages_status:
        summary_log.append(f"{Colors.GREEN}System Packages: SUCCESS{Colors.NC}")
    else:
        summary_log.append(f"{Colors.YELLOW}System Packages: PARTIAL/FAILED (Check logs for details){Colors.NC}")

    if python_tools_status:
        summary_log.append(f"{Colors.GREEN}Python Tools: SUCCESS{Colors.NC}")
    else:
        summary_log.append(f"{Colors.YELLOW}Python Tools: PARTIAL/FAILED (Check logs for details){Colors.NC}")

    if git_repos_status:
        summary_log.append(f"{Colors.GREEN}Git Repositories: SUCCESS{Colors.NC}")
    else:
        summary_log.append(f"{Colors.YELLOW}Git Repositories: PARTIAL/FAILED (Check logs for details){Colors.NC}")

    summary_log.append(f"{Colors.GREEN}====================================={Colors.NC}")

    # Print summary to console
    for line in summary_log:
        print(line)

    # Write summary to logs.txt
    with open("logs.txt", "w") as f:
        # Remove ANSI escape codes for the log file
        clean_summary = [re.sub(r'\x1b\[([0-9]{1,2};)?([0-9]{1,2})?m', '', line) for line in summary_log]
        f.write("\n".join(clean_summary))

    print(f"{Colors.GREEN}Installation summary written to logs.txt{Colors.NC}")

def install_single(tool_name):
    print(f"{Colors.CYAN}Attempting to install single tool: {tool_name}{Colors.NC}")

    tool_name_lower = tool_name.lower()
    if tool_name_lower not in ALL_TOOLS_LOWER_MAP:
        print(f"\n{Colors.RED}Error: Tool '{tool_name}' not found.{Colors.NC}")
        print(f"{Colors.YELLOW}run 'huntools display -a' to see the list of available tools.{Colors.NC}\n")
        return

    actual_tool_name = ALL_TOOLS_LOWER_MAP[tool_name_lower]
    tool = ALL_TOOLS[actual_tool_name]

    existing_path = shutil.which(actual_tool_name)
    if existing_path:
        print(f"{Colors.GREEN}{actual_tool_name} is already installed at {Colors.MAGENTA}{existing_path}{Colors.GREEN}. Skipping installation.{Colors.NC}")
        return

    tool_type = tool["type"]

    if tool_type == "go":
        print(f"{Colors.CYAN}Installing Go tool: {actual_tool_name}{Colors.NC}")
        subprocess.run(tool["install"], shell=True)
    
    elif tool_type == "package":
        print(f"{Colors.CYAN}Installing package: {actual_tool_name}{Colors.NC}")
        package_manager = get_package_manager()
        if not package_manager:
            print(f"{Colors.RED}Unsupported OS for package installation.{Colors.NC}")
            return
        if package_manager == "apt-get":
            subprocess.run(f"sudo {package_manager} install -y {actual_tool_name}", shell=True)
        elif package_manager == "yum":
            subprocess.run(f"sudo {package_manager} install -y {actual_tool_name}", shell=True)
        elif package_manager == "pacman":
            subprocess.run(f"sudo {package_manager} -S --noconfirm {actual_tool_name}", shell=True)
        elif package_manager == "brew":
            subprocess.run(f"{package_manager} install {actual_tool_name}", shell=True)

    elif tool_type == "python_git":
        print(f"{Colors.CYAN}Installing Python tool from git: {actual_tool_name}{Colors.NC}")
        install_dir = os.path.join(os.environ["HOME"], ".huntools", "python")
        os.makedirs(install_dir, exist_ok=True)
        repo_url = tool["url"]
        repo_path = os.path.join(install_dir, actual_tool_name)
        subprocess.run(["git", "clone", repo_url, repo_path])
        


    elif tool_type == "pip":
        print(f"{Colors.CYAN}Installing Python tool from pip: {actual_tool_name}{Colors.NC}")
        subprocess.run([sys.executable, "-m", "pip", "install", actual_tool_name])

    elif tool_type == "git":
        print(f"{Colors.CYAN}Cloning git repository: {actual_tool_name}{Colors.NC}")

def reinstall_single(tool_name, force=False):
    print(f"{Colors.CYAN}--- Reinstalling {tool_name} ---{Colors.NC}")

    tool_name_lower = tool_name.lower()
    if tool_name_lower not in ALL_TOOLS_LOWER_MAP:
        print(f"\n{Colors.RED}Error: Tool '{tool_name}' not found.{Colors.NC}")
        print(f"{Colors.YELLOW}run 'huntools display --all' to see the list of available tools.{Colors.NC}\n")
        return

    actual_tool_name = ALL_TOOLS_LOWER_MAP[tool_name_lower]
    remove_single(actual_tool_name, force)
    install_single(actual_tool_name)
    print(f"\n{Colors.GREEN}--- Reinstallation of {actual_tool_name} complete! ---{Colors.NC}")

def display_all():
    print(f"{Colors.CYAN}Available tools:{Colors.NC}")
    all_tools = sorted(ALL_TOOLS.keys(), key=str.lower)
    if not all_tools:
        print(f"{Colors.YELLOW}  No tools available.{Colors.NC}")
        return

    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        terminal_width = 80  
    max_len = max(len(tool) for tool in all_tools)

    base_entry_width = max_len + 2
    min_column_spacing = 2
    

    effective_column_width = base_entry_width + min_column_spacing

    num_columns = max(1, terminal_width // effective_column_width)
    
    if num_columns == 1:
        for tool in all_tools:
            print(f"{Colors.GREEN}- {tool}{Colors.NC}")
        return

    
    for i in range(0, len(all_tools), num_columns):
        row_tools = all_tools[i:i + num_columns]
        row_output_parts = []
        for tool in row_tools:
            row_output_parts.append(f"{Colors.GREEN}- {tool:<{max_len}}{Colors.NC}")

        print((" " * min_column_spacing).join(row_output_parts))

def checking_health():
    print(f"{Colors.CYAN}Performing health check on all tools...{Colors.NC}")
    all_tool_names = sorted(ALL_TOOLS.keys())
    installed_count = 0
    total_tools = len(all_tool_names)

    for tool_name in all_tool_names:
        tool = ALL_TOOLS[tool_name]
        tool_type = tool["type"]
        
        is_installed = False
        
        tool_path = shutil.which(tool_name)
        if tool_path:
            print(f"  - {tool_name}: {Colors.GREEN}Installed{Colors.NC} {Colors.YELLOW}(at {tool_path}){Colors.NC}")
            is_installed = True
        
        elif tool_type == "python_git":
            repo_path = os.path.join(os.environ["HOME"], ".huntools", "python", tool_name)
            if os.path.exists(repo_path):
                print(f"  - {tool_name}: {Colors.GREEN}Installed (Python Git Repo){Colors.NC} {Colors.YELLOW}(at {repo_path}){Colors.NC}")
                is_installed = True
        
        elif tool_type == "git":
            repo_path = os.path.join(os.environ["HOME"], ".huntools", "git", tool_name)
            if os.path.exists(repo_path):
                print(f"  - {tool_name}: {Colors.GREEN}Installed (Git Repo){Colors.NC} {Colors.YELLOW}(at {repo_path}){Colors.NC}")
                is_installed = True

        if is_installed:
            installed_count += 1
        else:
            print(f"  - {tool_name}: {Colors.RED}Not Found{Colors.NC}")
    
    print(f"\n{Colors.CYAN}Summary: {installed_count}/{total_tools} tools installed.{Colors.NC}")

def update_single(tool_name):
    print(f"{Colors.CYAN}Updating single tool: {tool_name}{Colors.NC}")

    if tool_name not in ALL_TOOLS:
        print(f"\n{Colors.RED}Error: Tool '{tool_name}' not found.{Colors.NC}")
        print(f"{Colors.YELLOW}run 'huntools display --all' to see the list of available tools.{Colors.NC}\n")
        return

    tool = ALL_TOOLS[tool_name]
    tool_type = tool["type"]

    if tool_type == "go":
        subprocess.run(tool["install"], shell=True)

    elif tool_type == "pip":
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", tool_name])

    elif tool_type == "python_git":
        repo_path = os.path.join(os.environ["HOME"], ".huntools", "python", tool_name)
        if os.path.exists(repo_path):
            subprocess.run(["git", "-C", repo_path, "pull"])
        else:
            print(f"{Colors.YELLOW}Tool {tool_name} not found in {repo_path}. Cannot update.{Colors.NC}")

    elif tool_type == "git":
        repo_path = os.path.join(os.environ["HOME"], ".huntools", "git", tool_name)
        if os.path.exists(repo_path):
            subprocess.run(["git", "-C", repo_path, "pull"])
        else:
            print(f"{Colors.YELLOW}Tool {tool_name} not found in {repo_path}. Cannot update.{Colors.NC}")

    elif tool_type == "package":
        package_manager = get_package_manager()
        if package_manager == "apt-get":
            subprocess.run(f"sudo {package_manager} install --only-upgrade -y {tool_name}", shell=True)
        elif package_manager == "yum":
            subprocess.run(f"sudo {package_manager} update -y {tool_name}", shell=True)
        elif package_manager == "pacman":
            print(f"{Colors.YELLOW}For Arch Linux, please run 'sudo pacman -Syu' to update all packages.{Colors.NC}")
        elif package_manager == "brew":
            subprocess.run(f"brew upgrade {tool_name}", shell=True)
def update_all():
    print(f"{Colors.CYAN}--- Updating all tools ---{Colors.NC}")
    
    package_manager = get_package_manager()
    package_tools = [name for name, tool in ALL_TOOLS.items() if tool["type"] == "package"]

    if package_manager and package_tools:
        print(f"{Colors.GREEN}Updating system packages via {package_manager}...{Colors.NC}")
        try:
            if package_manager == "apt-get":
                update_command = f"sudo {package_manager} update -y"
                subprocess.run(update_command, shell=True, check=True, capture_output=True)
                
                install_command = f"sudo {package_manager} install --only-upgrade -y {' '.join(package_tools)}"
                subprocess.run(install_command, shell=True, check=True, capture_output=True)

            elif package_manager == "yum":
                command = f"sudo {package_manager} update -y {' '.join(package_tools)}"
                subprocess.run(command, shell=True, check=True, capture_output=True)

            elif package_manager == "pacman":
                 print(f"{Colors.YELLOW}For Arch Linux, all packages are updated together. Running full system upgrade...{Colors.NC}")
                 command = f"sudo {package_manager} -Syu --noconfirm"
                 subprocess.run(command, shell=True, check=True, capture_output=True)

            elif package_manager == "brew":
                command = f"brew upgrade {' '.join(package_tools)}"
                subprocess.run(command, shell=True, check=True, capture_output=True)

            print(f"{Colors.GREEN}System packages updated.{Colors.NC}\n")
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}Error updating system packages: {e}{Colors.NC}")
            print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
            print(f"{Colors.YELLOW}Continuing with other tool updates...{Colors.NC}\n")
    else:
        print(f"{Colors.YELLOW}No system packages to update or package manager not supported.{Colors.NC}\n")

    for tool_name, tool_info in ALL_TOOLS.items():
        if tool_info["type"] == "package":
            continue 

        print(f"{Colors.CYAN}Updating {tool_name}...{Colors.NC}")
        tool_type = tool_info["type"]
        try:
            if tool_type == "go":
                subprocess.run(tool_info["install"], shell=True, check=True, capture_output=True)
            elif tool_type == "pip":
                subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", tool_name], check=True, capture_output=True)
            elif tool_type == "python_git":
                repo_path = os.path.join(os.environ["HOME"], ".huntools", "python", tool_name)
                if os.path.exists(repo_path):
                    subprocess.run(["git", "-C", repo_path, "pull"], check=True, capture_output=True)
                else:
                    print(f"{Colors.YELLOW}Tool {tool_name} (python_git) not found at {repo_path}. Skipping update.{Colors.NC}")
                    continue
            elif tool_type == "git":
                repo_path = os.path.join(os.environ["HOME"], ".huntools", "git", tool_name)
                if os.path.exists(repo_path):
                    subprocess.run(["git", "-C", repo_path, "pull"], check=True, capture_output=True)
                else:
                    print(f"{Colors.YELLOW}Tool {tool_name} (git) not found at {repo_path}. Skipping update.{Colors.NC}")
                    continue
            
            print(f"{Colors.GREEN}{tool_name} updated successfully.{Colors.NC}")
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}Error updating {tool_name}: {e}{Colors.NC}")
            print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
        except Exception as e:
            print(f"{Colors.RED}An unexpected error occurred while updating {tool_name}: {e}{Colors.NC}")
    
    print(f"\n{Colors.GREEN}--- All tools update process completed ---{Colors.NC}")

def get_tool_location_and_command(tool_name, tool_info):
    tool_type = tool_info["type"]
    tool_location = "Unknown"
    removal_command = None
    needs_sudo = False

    if tool_type == "go":
        gopath_bin = os.path.join(config["PATHS"].get("go_bin_dir", DEFAULT_GO_BIN_DIR), tool_name)
        if os.path.exists(gopath_bin):
            tool_location = gopath_bin
            removal_command = ["rm", gopath_bin]
        else:
            tool_path = shutil.which(tool_name)
            if tool_path:
                tool_location = tool_path
                removal_command = ["rm", tool_path]
        if tool_location.startswith("/usr/local/bin") or tool_location.startswith("/usr/bin"):
            needs_sudo = True

    elif tool_type == "pip":
        tool_location = f"Installed via pip (executable likely in PATH)"
        removal_command = [sys.executable, "-m", "pip", "uninstall", "-y", tool_name]
        if sys.prefix != sys.base_prefix: 
            if not os.access(os.path.join(sys.prefix, 'bin'), os.W_OK): 
                needs_sudo = True


    elif tool_type == "python_git":
        repo_path = os.path.join(config["PATHS"].get("python_dir", os.path.join(os.environ["HOME"], ".huntools", "python")),
 tool_name)
        if os.path.exists(repo_path):
            tool_location = repo_path
            removal_command = ["rm", "-rf", repo_path]
        else:
            tool_location = f"Repository not found at {repo_path}"

    elif tool_type == "git":
        repo_path = os.path.join(config["PATHS"].get("git_dir", os.path.join(os.environ["HOME"], ".huntools", "git")),
 tool_name)
        if os.path.exists(repo_path):
            tool_location = repo_path
            removal_command = ["rm", "-rf", repo_path]
        else:
            tool_location = f"Repository not found at {repo_path}"

    elif tool_type == "package":
        package_manager = get_package_manager()
        if package_manager:
            tool_location = f"Managed by {package_manager}"
            if package_manager in ["apt-get", "yum"]:
                removal_command = ["sudo", package_manager, "remove", "-y", tool_name]
                needs_sudo = True
            elif package_manager == "pacman":
                removal_command = ["sudo", package_manager, "-Rns", "--noconfirm", tool_name]
                needs_sudo = True
            elif package_manager == "brew":
                removal_command = [package_manager, "uninstall", tool_name]
        else:
            tool_location = "System package (unsupported OS)"

    return tool_location, removal_command, needs_sudo


def remove_single(tool_name, force=False):
    print(f"{Colors.CYAN}Removing single tool: {tool_name}{Colors.NC}")

    tool_name_lower = tool_name.lower()
    if tool_name_lower not in ALL_TOOLS_LOWER_MAP:
        print(f"\n{Colors.RED}Error: Tool '{tool_name}' not found.{Colors.NC}")
        print(f"{Colors.YELLOW}run 'huntools display --all' to see the list of available tools.{Colors.NC}\n")
        return

    actual_tool_name = ALL_TOOLS_LOWER_MAP[tool_name_lower]
    tool_info = ALL_TOOLS[actual_tool_name]

    if not _is_tool_installed(actual_tool_name, tool_info):
        print(f"{Colors.YELLOW}Tool '{tool_name}' is not currently installed. Skipping removal.{Colors.NC}\n")
        return
    
    tool_location, removal_command, needs_sudo = get_tool_location_and_command(actual_tool_name, tool_info)

    if not force:
        if tool_location == "Unknown" or (tool_info["type"] in ["python_git", "git"] and not os.path.exists(tool_location)):
            print(f"{Colors.YELLOW}⚠️  Warning: Could not determine the exact installation path for {tool_name}. Proceeding with generic removal attempt.{Colors.NC}")

        warning_message = f"{Colors.RED}⚠️  WARNING: You are about to remove {tool_name}.\n"
        warning_message += f"📍 Location: {Colors.CYAN}{tool_location}{Colors.NC}{Colors.RED}"
        if needs_sudo:
            warning_message += f"\n{Colors.RED}🚨 This tool is in a system-protected directory and may require 'sudo'.{Colors.NC}"
        print(warning_message)

        confirmation = input(f"{Colors.YELLOW}Are you sure you want to proceed? (yes/no): {Colors.NC}").lower()
        if confirmation != 'yes':
            print(f"{Colors.BLUE}Removal of {tool_name} aborted.{Colors.NC}")
            return
    else:
        print(f"{Colors.GREEN}Force removal of {tool_name} initiated.{Colors.NC}")

    tool_type = tool_info["type"]
    try:
        if tool_type == "go":
            go_bin_dir = config["PATHS"].get("go_bin_dir", os.path.join(os.environ["HOME"], "go", "bin"))
            go_tool_path = os.path.join(go_bin_dir, tool_name)

            if os.path.exists(go_tool_path):
                try:
                    os.remove(go_tool_path)
                    print(f"{Colors.GREEN}Removed {tool_name} from {go_tool_path}.{Colors.NC}")
                except OSError as e:
                    print(f"{Colors.RED}Error removing {tool_name} from {go_tool_path}: {e}{Colors.NC}")
                    print(f"{Colors.YELLOW}If this is a permission error, try running with 'sudo'.{Colors.NC}")
            else:
                tool_path_from_which = shutil.which(tool_name)
                if tool_path_from_which:
                    try:
                        os.remove(tool_path_from_which)
                        print(f"{Colors.GREEN}Removed {tool_name} from {tool_path_from_which}.{Colors.NC}")
                    except OSError as e:
                        print(f"{Colors.RED}Error removing {tool_name} from {tool_path_from_which}: {e}{Colors.NC}")
                        print(f"{Colors.YELLOW}If this is a permission error, try running with 'sudo'.{Colors.NC}")
                else:
                    print(f"{Colors.RED}Error: {tool_name} not found in configured Go binary directory ({go_bin_dir}) or system PATH for removal.{Colors.NC}")

        elif tool_type == "pip":
            subprocess.run(removal_command, check=True)
            print(f"{Colors.GREEN}Removed {tool_name} via pip.{Colors.NC}")

        elif tool_type == "python_git" or tool_type == "git":
            if os.path.exists(tool_location): 
                shutil.rmtree(tool_location)
                print(f"{Colors.GREEN}Removed {tool_name} repository from {tool_location}.{Colors.NC}")
            else:
                print(f"{Colors.RED}Error: Repository for {tool_name} not found at {tool_location} for removal.{Colors.NC}")

        elif tool_type == "package":
            if removal_command:
                subprocess.run(removal_command, check=True)
                print(f"{Colors.GREEN}Removed {tool_name} via package manager.{Colors.NC}")
            else:
                print(f"{Colors.RED}Error: Could not find package manager removal command for {tool_name}.{Colors.NC}")

    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}Error removing {tool_name}: {e}{Colors.NC}")
        if e.stderr:
            print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
        print(f"{Colors.YELLOW}If this is a permission error, try running with 'sudo'.{Colors.NC}")
    except OSError as e:
        print(f"{Colors.RED}Error removing {tool_name}: {e}{Colors.NC}")
        print(f"{Colors.YELLOW}If this is a permission error, try running with 'sudo'.{Colors.NC}")
def get_installed_tools_count():
    installed_count = 0
    for tool_name, tool_info in ALL_TOOLS.items():
        is_installed = False
        
        # Check if the tool is in the PATH
        tool_path = shutil.which(tool_name)
        if tool_path:
            is_installed = True
        
        elif tool_info["type"] == "python_git":
            repo_path = os.path.join(DEFAULT_PYTHON_INSTALL_DIR, tool_name)
            if os.path.exists(repo_path):
                is_installed = True
        
        elif tool_info["type"] == "git":
            repo_path = os.path.join(DEFAULT_GIT_INSTALL_DIR, tool_name)
            if os.path.exists(repo_path):
                is_installed = True

        if is_installed:
            installed_count += 1
    return installed_count


def remove_all(force=False):
    installed_tool_count = get_installed_tools_count()
    warning_message = f"{Colors.RED}⚠️  WARNING: You are about to remove {installed_tool_count} currently installed huntools. This action is irreversible.{Colors.NC}"
    print(warning_message)
    if not force:
        confirmation = input(f"{Colors.YELLOW}Are you sure you want to proceed? (yes/no): {Colors.NC}").lower()
        if confirmation != 'yes':
            print(f"{Colors.BLUE}Removal aborted.{Colors.NC}")
            return

    print(f"{Colors.BLUE}--- Removing all installed tools ---{Colors.NC}")
    
    for tool_name in list(ALL_TOOLS.keys()): 
        remove_single(tool_name)

    huntools_dir = config["PATHS"].get("install_dir", DEFAULT_HUNTOOLS_INSTALL_DIR)
    if os.path.exists(huntools_dir):
        print(f"{Colors.BLUE}Removing huntools installation directory: {huntools_dir}{Colors.NC}")
        try:
            shutil.rmtree(huntools_dir)
            print(f"{Colors.GREEN}Removed {huntools_dir}.{Colors.NC}")
        except OSError as e:
            print(f"{Colors.RED}Error removing {huntools_dir}: {e}{Colors.NC}")
            print(f"{Colors.YELLOW}If this is a permission error, try running with 'sudo'.{Colors.NC}")

    print(f"\n{Colors.GREEN}--- All tools removal process completed ---{Colors.NC}")
    print(f"{Colors.YELLOW}Note: Some system packages might require manual removal if not fully uninstalled by individual tool removal.{Colors.NC}")

def clean_all(force=False):
    warning_message = f"{Colors.RED}⚠️  WARNING: You are about to purge delete all data, including configuration. This action is irreversible.{Colors.NC}"
    print(warning_message)
    if not force:
        confirmation = input(f"{Colors.YELLOW}Are you sure you want to proceed? (yes/no): {Colors.NC}").lower()
        if confirmation != 'yes':
            print(f"{Colors.CYAN}Purge aborted.{Colors.NC}")
            return

    print(f"{Colors.CYAN}Purging all huntools data...{Colors.NC}")
    remove_all()
    config_dir_to_remove = config["PATHS"].get("config_file", CONFIG_DIR)
    if os.path.exists(config_dir_to_remove):
        shutil.rmtree(config_dir_to_remove)
    
    huntools_system_path = "/usr/local/bin/huntools"
    if os.path.exists(huntools_system_path):
        print(f"{Colors.CYAN}Removing system-wide huntools executable...{Colors.NC}")
        try:
            command = f"sudo rm {huntools_system_path}"
            print(f"Running command: {command}")
            process = subprocess.run(command, shell=True, check=False, capture_output=True)
            if process.returncode == 0:
                print(f"{Colors.GREEN}Removed {huntools_system_path}.{Colors.NC}")
            else:
                print(f"{Colors.RED}Error removing {huntools_system_path}.{Colors.NC}")
                if process.stderr:
                    print(f"{Colors.RED}Stderr: {process.stderr.decode()}{Colors.NC}")
                print(f"{Colors.YELLOW}You may need to remove it manually: sudo rm {huntools_system_path}{Colors.NC}")
        except Exception as e:
            print(f"{Colors.RED}An unexpected error occurred: {e}{Colors.NC}")

    print(f"{Colors.GREEN}All huntools data has been removed.{Colors.NC}")

def self_update():
    print(f"{Colors.CYAN}Updating huntools...{Colors.NC}")
    
    git_repo_path = config.get("PATHS", {}).get("git_repo_path")
    if not git_repo_path or not os.path.exists(os.path.join(git_repo_path, ".git")):
        print(f"{Colors.RED}Huntools git repository path not found or invalid.{Colors.NC}")
        print(f"{Colors.YELLOW}Please run the system-wide installation again from within the git repository to set the path:{Colors.NC}")
        print(f"  ./huntools.py install -is")
        return

    try:
        print(f"{Colors.CYAN}Pulling latest changes from git...{Colors.NC}")
        subprocess.run(["git", "-C", git_repo_path, "pull"], check=True)
        print(f"{Colors.GREEN}huntools updated successfully from git.{Colors.NC}")

        install_dir = get_install_path()
        destination_path = os.path.join(install_dir, "huntools")

        if os.path.exists(destination_path):
            print(f"{Colors.CYAN}System-wide installation detected. Updating executable...{Colors.NC}")
            try:
                huntools_local_path = os.path.join(git_repo_path, "huntools.py")
                command = f"sudo cp {huntools_local_path} {destination_path} && sudo chmod +x {destination_path}"
                
                print(f"Running command: {Colors.GREEN}{command}{Colors.NC}")
                
                process = subprocess.run(command, shell=True, check=False, capture_output=True)
                
                if process.returncode == 0:
                    print(f"{Colors.GREEN}System-wide executable updated successfully to {destination_path}.{Colors.NC}")
                else:
                    print(f"{Colors.RED}Error updating system-wide executable.{Colors.NC}")
                    if process.stderr:
                        print(f"{Colors.RED}Stderr: {process.stderr.decode()}{Colors.NC}")
                    print(f"{Colors.YELLOW}You may need to run 'sudo ./huntools.py install -is' again manually.{Colors.NC}")
            
            except Exception as e:
                print(f"{Colors.RED}An unexpected error occurred while updating the system-wide executable: {e}{Colors.NC}")

    except subprocess.CalledProcessError:
        print(f"{Colors.RED}Update failed. Please make sure you are in the huntools git repository.{Colors.NC}")

def show_path():
    print(f"{Colors.NC}Displaying huntools paths:{Colors.NC}")
    install_dir = config["PATHS"].get("install_dir", DEFAULT_HUNTOOLS_INSTALL_DIR)
    python_dir = config["PATHS"].get("python_dir", DEFAULT_PYTHON_INSTALL_DIR)
    git_dir = config["PATHS"].get("git_dir", DEFAULT_GIT_INSTALL_DIR)
    go_bin_dir = config["PATHS"].get("go_bin_dir", DEFAULT_GO_BIN_DIR)
    config_file_path = config["PATHS"].get("config_file", os.path.join(CONFIG_DIR, "config.yml"))

    print(f"{Colors.NC}  - Installation directory: {Colors.GREEN}{install_dir}{Colors.NC}")
    print(f"{Colors.NC}  - Python tools directory: {Colors.GREEN}{python_dir}{Colors.NC}")
    print(f"{Colors.NC}  - Git repos directory: {Colors.GREEN}{git_dir}{Colors.NC}")
    print(f"{Colors.NC}  - Go binary path: {Colors.GREEN}{go_bin_dir}{Colors.NC}")
    print(f"{Colors.NC}  - Config file: {Colors.GREEN}{config_file_path}{Colors.NC}")

def show_changelog():
    url = "https://raw.githubusercontent.com/l0n3m4n/huntools/refs/heads/main/CHANGELOG.md"
    try:
        with urllib.request.urlopen(url) as response:
            changelog_content = response.read().decode('utf-8')

        for line in changelog_content.splitlines():
            line = line.rstrip()

            if line.startswith("# "):
                print(f"{Colors.BOLD_RED}{line.replace('# ', '')}{Colors.NC}")
            elif line.startswith("## "):
                print(f"{Colors.CYAN}{line.replace('## ', '')}{Colors.NC}")
            elif line.startswith("### "):
                print(f"{Colors.MAGENTA}{line.replace('### ', '')}{Colors.NC}")
            elif line.startswith("- "):
                formatted_line = line.replace("- ", f"{Colors.GREEN}- {Colors.NC}")
                formatted_line = re.sub(r'\*\*(.*?)\*\*', f'{Colors.YELLOW}\1{Colors.NC}', formatted_line) # Bold
                formatted_line = re.sub(r'_(.*?)_', f'{Colors.ITALIC}\1{Colors.NC}', formatted_line) # Italics with underscore
                formatted_line = re.sub(r'\*(.*?)\*', f'{Colors.ITALIC}\1{Colors.NC}', formatted_line) # Italics with asterisk
                formatted_line = re.sub(r'`(.*?)`', f'{Colors.BLUE}\1{Colors.NC}', formatted_line) # Inline code
                print(formatted_line)
            elif not line.strip():
                print(line)
            else:
                formatted_line = line
                formatted_line = re.sub(r'\*\*(.*?)\*\*', f'{Colors.YELLOW}\1{Colors.NC}', formatted_line) # Bold
                formatted_line = re.sub(r'_(.*?)_', f'{Colors.ITALIC}\1{Colors.NC}', formatted_line) # Italics with underscore
                formatted_line = re.sub(r'\*(.*?)\*', f'{Colors.ITALIC}\1{Colors.NC}', formatted_line) # Italics with asterisk
                formatted_line = re.sub(r'`(.*?)`', f'{Colors.BLUE}\1{Colors.NC}', formatted_line) # Inline code
                print(f"{Colors.NC}{formatted_line}{Colors.NC}")

    except Exception as e:
        print(f"{Colors.RED}Failed to fetch changelog from URL: {e}{Colors.NC}")

def generate_dockerfile(filename=None):
    dockerfile_content = '''# Use an official Python runtime as a parent image
FROM python:3.10-slim-buster

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
# This assumes a Debian-based system (buster)
# We need git, curl, wget, build-essential, gcc, cmake, libpcap-dev, dnsutils, libssl-dev, libffi-dev, libxml2-dev, libxslt1-dev, zlib1g-dev
# Go will be installed by huntools itself
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    build-essential \
    gcc \
    cmake \
    libpcap-dev \
    dnsutils \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    ruby \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /app
COPY . /app

# Install huntools and all its managed tools
# This will also install Go if not present
# We need to ensure huntools.py is executable
RUN chmod +x huntools.py && ./huntools.py install -a

# Set environment variables for Go (if huntools installed it)
ENV GOROOT=/usr/local/go
ENV GOPATH=/root/go
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH

# Expose any ports if necessary (e.g., for web tools) - customize as needed
# EXPOSE 8080

# Define the default command to run when the container starts
# This will give a shell where huntools and other tools are available
CMD ["bash"]

# Alternatively, to run huntools directly:
# ENTRYPOINT ["./huntools.py"]
# CMD ["--help"]
'''
    if filename:
        try:
            with open(filename, "w") as f:
                f.write(dockerfile_content)
            print(f"{Colors.NC}Dockerfile successfully generated: {Colors.GREEN}{os.path.abspath(filename)}{Colors.NC}")
        except IOError as e:
            print(f"{Colors.RED}Error writing Dockerfile to {filename}: {e}{Colors.NC}")
    else:
        print(f"{Colors.BLUE}{dockerfile_content}{Colors.NC}")


class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action(self, action):
        if isinstance(action, argparse._SubParsersAction):
            parts = [""] 
            max_len = 0
            for subparser_action in action._choices_actions:
                max_len = max(max_len, len(subparser_action.dest))

            for subparser_action in action._choices_actions:
                if subparser_action.help: 
                    parts.append(f"    {Colors.YELLOW}{subparser_action.dest:<{max_len}}{Colors.NC}    {Colors.GREEN}{subparser_action.help}{Colors.NC}") # Add more indentation
            return "\n".join(parts)
        else:
            action_header = self._format_action_invocation(action)
            
            help_text = self._expand_help(action)
            
            if help_text:
                return f"  {action_header} {help_text}\n"
            else:
                return f"  {action_header}\n"

    def _format_action_invocation(self, action):
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return f"{Colors.YELLOW}{metavar}{Colors.NC}"
        else:
            parts = []
            if action.nargs == 0:
                parts.extend([f"{Colors.YELLOW}{s}{Colors.NC}" for s in action.option_strings])
            else:
                default = self._get_default_metavar_for_optional(action)
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    parts.append(f'{Colors.YELLOW}{option_string}{Colors.NC} {Colors.CYAN}{args_string}{Colors.NC}')
            return ', '.join(parts)

    def _format_text(self, text):
        if text:
            return f'{Colors.WHITE}{super()._format_text(text)}{Colors.NC}'
        return ''

    def _expand_help(self, action):
        return f'{Colors.GREEN}{super()._expand_help(action)}{Colors.NC}'

    def _format_action_group_name(self, action_group):
        if action_group.title is None:
            return ''
        return f"{Colors.YELLOW}{action_group.title}:{Colors.NC}\n"


# Main function to parse arguments and execute commands 
def main():
    try:
        load_config()
        show_banner()

        parser = argparse.ArgumentParser(
            description="A streamlined tool for managing your bug hunting arsenal.",
            formatter_class=CustomHelpFormatter,
            usage="huntools <command> [flags]"
        )

        subparsers = parser.add_subparsers(dest="command", title="Available commands", metavar=" ")

        # Install command
        install_parser = subparsers.add_parser("install", help="Install tools", add_help=False, formatter_class=CustomHelpFormatter)
        install_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        install_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        install_parser.add_argument("-s", dest="install_single", help="Install a single, specified tool from the available list.", metavar="TOOL")
        install_parser.add_argument("--single", dest="install_single", help=argparse.SUPPRESS, metavar="TOOL")
        install_parser.add_argument("-a", dest="install_all", action="store_true", help="Install all available tools.")
        install_parser.add_argument("--all", dest="install_all", action="store_true", help=argparse.SUPPRESS)
        install_parser.add_argument("-is", dest="install_system", action="store_true", help="Install huntools itself to the system (e.g., /usr/local/bin).")
        install_parser.add_argument("--install-system", dest="install_system", action="store_true", help=argparse.SUPPRESS)

        # Reinstall command
        reinstall_parser = subparsers.add_parser("reinstall", help="Reinstall a tool", add_help=False, formatter_class=CustomHelpFormatter)
        reinstall_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        reinstall_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        reinstall_parser.add_argument("tool_name", help="The name of the tool to reinstall")
        reinstall_parser.add_argument("-f", "--force", dest="force_remove", action="store_true", help="Bypass confirmation prompts for removal actions.")

        # Update command
        update_parser = subparsers.add_parser("update", help="Update tools", add_help=False, formatter_class=CustomHelpFormatter)
        update_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        update_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        update_parser.add_argument("-s", dest="update_single", help="Update a single, specified tool to its latest version.", metavar="TOOL")
        update_parser.add_argument("--single", dest="update_single", help=argparse.SUPPRESS, metavar="TOOL")
        update_parser.add_argument("--single-update", dest="update_single", help=argparse.SUPPRESS, metavar="TOOL")
        update_parser.add_argument("-ua", dest="update_all", action="store_true", help="Update all installed tools.")
        update_parser.add_argument("--all", dest="update_all", action="store_true", help=argparse.SUPPRESS)
        update_parser.add_argument("--update-all", dest="update_all", action="store_true", help=argparse.SUPPRESS)
        update_parser.add_argument("-su", dest="self_update", action="store_true", help="Update huntools to the latest version.")
        update_parser.add_argument("--self-update", dest="self_update", action="store_true", help=argparse.SUPPRESS)
        update_parser.add_argument("--self", dest="self_update", action="store_true", help=argparse.SUPPRESS)
        update_parser.add_argument("--update-self", dest="self_update", action="store_true", help=argparse.SUPPRESS)

        # Remove command
        remove_parser = subparsers.add_parser("remove", help="Remove tools", add_help=False, formatter_class=CustomHelpFormatter)
        remove_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        remove_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        remove_parser.add_argument("-rs", dest="remove_single", help="Remove a single, specified tool.", metavar="TOOL")
        remove_parser.add_argument("--single", dest="remove_single", help=argparse.SUPPRESS, metavar="TOOL")
        remove_parser.add_argument("--remove-single", dest="remove_single", help=argparse.SUPPRESS, metavar="TOOL")
        remove_parser.add_argument("-ra", dest="remove_all", action="store_true", help="Remove all installed tools.")
        remove_parser.add_argument("--all", dest="remove_all", action="store_true", help=argparse.SUPPRESS)
        remove_parser.add_argument("--remove-all", dest="remove_all", action="store_true", help=argparse.SUPPRESS)
        remove_parser.add_argument("-ca", dest="clean_all", action="store_true", help="Purge all huntools data, including configurations and installed tools.")
        remove_parser.add_argument("--clean", dest="clean_all", action="store_true", help=argparse.SUPPRESS)
        remove_parser.add_argument("--clean-all", dest="clean_all", action="store_true", help=argparse.SUPPRESS)
        remove_parser.add_argument("-f", dest="force_remove", action="store_true", help="Bypass confirmation prompts for removal actions.")
        remove_parser.add_argument("--force", dest="force_remove", action="store_true", help=argparse.SUPPRESS)

        # Other commands
        display_parser = subparsers.add_parser("display", help="Display all tools", add_help=False, formatter_class=CustomHelpFormatter)
        display_parser.add_argument("-a", dest="display_all", action="store_true", help="Show all tools available for installation.")
        display_parser.add_argument("--all", dest="display_all", action="store_true", help=argparse.SUPPRESS)
        display_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        display_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        
        check_parser = subparsers.add_parser("check", help="Check tool health", add_help=False, formatter_class=CustomHelpFormatter)
        check_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        check_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        check_parser.add_argument("-hc", dest="checking_health", action="store_true", help="Perform a health check on all installed tools.")

        show_parser = subparsers.add_parser("show", help="Show information", add_help=False, formatter_class=CustomHelpFormatter)
        show_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        show_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        show_parser.add_argument("-pl", dest="path", action="store_true", help="Display all relevant paths used by huntools.")
        show_parser.add_argument("--path", action="store_true", help=argparse.SUPPRESS)
        show_parser.add_argument("-cl", dest="changelog", action="store_true", help="View the latest changes and updates to huntools.")
        show_parser.add_argument("--changelog", action="store_true", help=argparse.SUPPRESS)

        config_parser = subparsers.add_parser("config", help="Configure huntools", add_help=False, formatter_class=CustomHelpFormatter)
        config_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        config_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        config_parser.add_argument("-cp", dest="config_path", help="Specify a custom path for the configuration file.\n    (Default: ~/.config/huntools/config.yml)")
        config_parser.add_argument("--path", dest="config_path", help=argparse.SUPPRESS)
        config_parser.add_argument("-bp", dest="binary_path", help="Set a custom directory for downloaded binaries.\n    (Default: ~/.huntools/bin)")
        config_parser.add_argument("--binary-path", dest="binary_path", help=argparse.SUPPRESS)
        config_parser.add_argument("-ip", dest="install_path", help="Define the installation directory for all tools.\n    (Default: ~/.huntools/)")
        config_parser.add_argument("--install-path", dest="install_path", help=argparse.SUPPRESS)

        # Docker command
        docker_parser = subparsers.add_parser("docker", help="Manage Docker image", add_help=False, formatter_class=CustomHelpFormatter)
        docker_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        docker_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        docker_parser.add_argument("-g", "--generate", action="store_true", help="Generate a Dockerfile for Huntools.")
        docker_parser.add_argument("-s", dest="save_filename", nargs='?', const="Dockerfile", help="Specify a filename to save the Dockerfile. Defaults to 'Dockerfile'.", metavar="FILENAME")
        docker_parser.add_argument("--save", dest="save_filename", nargs='?', const="Dockerfile", help=argparse.SUPPRESS, metavar="FILENAME")

        args = parser.parse_args()

        if not args.command:
            parser.print_help()
            sys.exit(1)

        if args.command == "install":
            if args.install_all:
                install_all()
            elif args.install_single:
                install_single(args.install_single)
            elif args.install_system:
                install_system()
            else:
                install_parser.print_help()
                sys.exit(1)
        elif args.command == "reinstall":
            reinstall_single(args.tool_name, args.force_remove)
        elif args.command == "display":
            if args.display_all:
                display_all()
            else:
                display_parser.print_help()
                sys.exit(1)
        elif args.command == "check":
            if args.checking_health:
                checking_health()
            else:
                check_parser.print_help()
                sys.exit(1)
        elif args.command == "update":
            if args.update_all:
                update_all()
            elif args.update_single:
                update_single(args.update_single)
            elif args.self_update:
                self_update()
            else:
                update_parser.print_help()
                sys.exit(1)
        elif args.command == "remove":
            if args.remove_all:
                remove_all(args.force_remove)
            elif args.remove_single:
                remove_single(args.remove_single, args.force_remove)
            elif args.clean_all:
                clean_all(args.force_remove)
            else:
                remove_parser.print_help()
                sys.exit(1)
        elif args.command == "show":
            if args.path:
                show_path()
            elif args.changelog:
                show_changelog()
            else:
                show_parser.print_help()
                sys.exit(1)
        elif args.command == "config":
            if args.config_path or args.binary_path or args.install_path:
                if args.config_path:
                    config["PATHS"]["config_file"] = args.config_path
                    print(f"{Colors.GREEN}Setting custom config file path to: {args.config_path}{Colors.NC}")
                if args.binary_path:
                    config["PATHS"]["go_bin_dir"] = args.binary_path
                    print(f"{Colors.GREEN}Setting custom Go binary path to: {args.binary_path}{Colors.NC}")
                if args.install_path:
                    config["PATHS"]["install_dir"] = args.install_path
                    config["PATHS"]["python_dir"] = os.path.join(args.install_path, "python")
                    config["PATHS"]["git_dir"] = os.path.join(args.install_path, "git")
                    print(f"{Colors.GREEN}Setting custom install path to: {args.install_path}{Colors.NC}")
                save_config()
            else:
                config_parser.print_help()
                sys.exit(1)
        elif args.command == "docker":
            if args.generate:
                if args.save_filename:
                    generate_dockerfile(filename=args.save_filename)
                else:
                    generate_dockerfile(filename="Dockerfile")
            else:
                docker_parser.print_help()
                sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}Installation aborted by user (Ctrl+C).{Colors.NC}")
        sys.exit(1)

if __name__ == "__main__":
    main()