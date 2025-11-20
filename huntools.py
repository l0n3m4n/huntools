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
import json
import concurrent.futures
from datetime import datetime
import logging


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


class ColoredFormatter(logging.Formatter):
    FORMAT = "[%(levelname)s] %(message)s"

    LOG_COLORS = {
        logging.DEBUG: Colors.BRIGHT_BLACK,
        logging.INFO: Colors.WHITE,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.BOLD_RED
    }

    def format(self, record):
        log_fmt = self.LOG_COLORS.get(record.levelno, Colors.NC) + self.FORMAT + Colors.NC
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


# The _log_error function is replaced by logging.error
# def _log_error(message):
#     clean_message = re.sub(r'\x1b\[([0-9]{1,2};)?([0-9]{1,2})?m', '', message)
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     with open("errors.log", "a") as f:
#         f.write(f"[{timestamp}] {clean_message}\n")

def setup_logging(verbose, debug):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO) # Default level

    if verbose:
        logger.setLevel(logging.INFO)
    if debug:
        logger.setLevel(logging.DEBUG)

    # Console handler with colored output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)

    # File handler for all logs
    file_handler = logging.FileHandler("huntools.log")
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    file_handler.setLevel(logging.DEBUG) # Capture all levels to file
    logger.addHandler(file_handler)

    # Separate file handler for errors.log (only ERROR and CRITICAL)
    error_file_handler = logging.FileHandler("errors.log")
    error_file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    error_file_handler.setLevel(logging.ERROR)
    logger.addHandler(error_file_handler)

    # Disable propagation to avoid duplicate messages from root logger
    logger.propagate = False


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
                                                                        
           Author: l0n3m4n | Version: 3.5.0 | {tool_count} Hunter Tools
\n'''
    print(f"{Colors.CYAN}{banner}{Colors.NC}", end="")




# Master Tool List: You can add more tools here as needed, and you can delete tools you don't want to install
ALL_TOOLS = {
    
    # Go Tools
    "ffuf": {"type": "go", "install": "go install -v github.com/ffuf/ffuf/v2@latest"},
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
    "metabigor": {"type": "go", "install": "go install -v github.com/j3ssie/metabigor@latest"},
    "gf": {"type": "go", "install": "go install -v github.com/tomnomnom/gf@latest"},
    "brutespray": {"type": "go", "install": "go install -v github.com/x90skysn3k/brutespray@latest"},
    "github-subdomains": {"type": "go", "install": "go install -v github.com/gwen001/github-subdomains@latest"},
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
    "gitleaks": {"type": "go", "install": "go install -v github.com/zricethezav/gitleaks/v8@latest"},
    "trufflehog": {"type": "go", "install": "rm -rf /tmp/trufflehog && git clone https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog && cd /tmp/trufflehog && make && mv /tmp/trufflehog/bin/trufflehog $HOME/.huntools/go", "size": "large"}, # NOTE: manual installation large size 
    "massdns": {"type": "go", "install": "rm -rf /tmp/massdns && git clone https://github.com/blechschmidt/massdns.git /tmp/massdns && cd /tmp/massdns && make && mv /tmp/massdns/bin/massdns $HOME/.huntools/go/"},
    "feroxbuster": {"type": "go", "install": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s -- $HOME/.huntools/go"},
    "unfurl": {"type": "go", "install": "go -v install github.com/tomnomnom/unfurl@latest"},
    "subzy": {"type": "go", "install": "go install -v github.com/PentestPad/subzy@latest"},
    "qsreplace": {"type": "go", "install": "go install -v github.com/tomnomnom/qsreplace@latest"}, 
    "vulnx": {"type": "go", "install": "go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@latest"},

    # Package Tools
    "jq": {"type": "package"}, # command-line JSON processor
    "flameshot": {"type": "package"}, # screenshot tool
    "lsd": {"type": "package"}, # debian package name is 'lsd', for arch is 'lsd-git' 

    # Python Git Tools
    "SSRFmap": {"type": "python_git", "url": "https://github.com/swisskyrepo/SSRFmap.git"},
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
    "pydictor": {"type": "python_git", "url": "https://github.com/landgrey/pydictor.git"},
    "smuggler": {"type": "python_git", "url": "https://github.com/defparam/smuggler.git"},
    "regulator": {"type": "python_git", "url": "https://github.com/cramppet/regulator.git"},
    "nomore403": {"type": "python_git", "url": "https://github.com/devploit/nomore403.git"},
    "SwaggerSpy": {"type": "python_git", "url": "https://github.com/UndeadSec/SwaggerSpy.git"},
    "LeakSearch": {"type": "python_git", "url": "https://github.com/JoelGMSec/LeakSearch.git"},
    "Spoofy": {"type": "python_git", "url": "https://github.com/MattKeeley/Spoofy.git"},
    "msftrecon": {"type": "python_git", "url": "https://github.com/Arcanum-Sec/msftrecon.git"},
    "Scopify": {"type": "python_git", "url": "https://github.com/Arcanum-Sec/Scopify.git"},
    "metagoofil": {"type": "python_git", "url": "https://github.com/opsdisk/metagoofil.git"},
    "dnsvalidator": {"type": "python_git", "url": "https://github.com/vortexau/dnsvalidator.git"},
    "ghauri": {"type": "python_git", "url": "https://github.com/r0oth3x49/ghauri.git"},
    "seclists": {"type": "python_git", "url": "https://github.com/danielmiessler/SecLists.git", "size": "large"}, # NOTE: manual intallation due to package size (2.6gb)
    "xsser" : {"type": "python_git", "url": "https://github.com/epsylon/xsser.git"}, 
    
    # Python Pip Tools
    "censys": {"type": "python_git", "url": "https://github.com/censys/censys-python.git"},
    "shodan": {"type": "python_git", "url": "https://github.com/achillean/shodan-python.git"},
    "wafw00f": {"type": "python_git", "url": "https://github.com/enablesecurity/wafw00f.git"},
    "commix": {"type": "python_git", "url": "https://github.com/commixproject/commix.git"},
    "urless": {"type": "python_git", "url": "https://github.com/xnl-h4ck3r/urless.git"},
    "xnLinkFinder": {"type": "python_git", "url": "https://github.com/xnl-h4ck3r/xnLinkFinder.git"},
    "xnldorker": {"type": "python_git", "url": "https://github.com/xnl-h4ck3r/xnldorker.git"},
    "porch-pirate": {"type": "python_git", "url": "https://github.com/MandConsultingGroup/porch-pirate.git"},
    "p1radup": {"type": "python_git", "url": "https://github.com/iambouali/p1radup.git"},
    "subwiz": {"type": "python_git", "url": "https://github.com/hadriansecurity/subwiz.git", "size": "large"}, # NOTE: need manual installation due to dependency and big package size
 
    # pip install 
    "waymore": {"type": "pip", "install": "waymore"}, 
    "dirsearch": {"type": "pip", "install": "dirsearch"},

    # Git Repos
    "crt-sh": {"type": "git", "url": "https://github.com/az7rb/crt.sh.git"},
    "Gf-Patterns": {"type": "git", "url": "https://github.com/1ndianl33t/Gf-Patterns.git"},
    "sus_params": {"type": "git", "url": "https://github.com/g0ldencybersec/sus_params.git"},
}


ALL_TOOLS_LOWER_MAP = {name.lower(): name for name in ALL_TOOLS.keys()}


# Global Variables 
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

def validate_config(config):
    """Validates the paths in the configuration."""
    if "PATHS" in config:
        for key, path in config["PATHS"].items():
            if key.endswith("_dir") and not os.path.isdir(path):
                logging.error(f"The directory '{path}' for '{key}' does not exist.")
                sys.exit(1)

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
    
    # Ensure default installation directories exist
    os.makedirs(config["PATHS"]["install_dir"], exist_ok=True)
    os.makedirs(config["PATHS"]["python_dir"], exist_ok=True)
    os.makedirs(config["PATHS"]["git_dir"], exist_ok=True)
    os.makedirs(DEFAULT_GO_WORKSPACE_DIR, exist_ok=True) # Ensure Go workspace exists
    os.makedirs(config["PATHS"]["go_bin_dir"], exist_ok=True) # Ensure Go bin directory exists
    
    validate_config(config)

def save_config():
    actual_config_file = config.get("PATHS", {}).get("config_file", os.path.join(CONFIG_DIR, "config.yml"))
    os.makedirs(os.path.dirname(actual_config_file), exist_ok=True) # Ensure directory exists for custom path
    with open(actual_config_file, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

def _is_tool_installed(tool_name, tool_info):
    # Check if the tool is in the PATH
    if shutil.which(tool_name.lower()):
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
    # Check if system dependencies are already installed (heuristic)
    # We check for git, python3, pip3, and a common build tool (gcc)
    # and poetry. If all are found, we assume system dependencies are met.
    all_present = True
    if not shutil.which("git"): all_present = False
    if not shutil.which("python3"): all_present = False
    if not shutil.which("pip3"): all_present = False
    if not shutil.which("gcc"): all_present = False
    if not shutil.which("poetry"): all_present = False

    if all_present:
        return True, True # Success, already installed

    package_manager = get_package_manager()
    if not package_manager:
        logging.error(f"Unsupported OS. Please install dependencies manually.")
        return False, False

    deps = {
        "apt-get": "python3 python3-pip python3-venv git ruby build-essential gcc cmake libpcap-dev dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev python3-setuptools rustc cargo",
        "yum": "python3 python3-pip python3-devel git ruby gcc gcc-c++ make cmake pcap-devel dnsutils openssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel python3-setuptools rust cargo",
        "pacman": "python python-pip python-virtualenv git ruby base-devel gcc cmake libpcap dnsutils openssl libffi libxml2 libxslt zlib python-setuptools rust",
        "brew": "python git curl wget ruby nmap cmake rust"
    }

    try:
        if package_manager == "apt-get":
            logging.info(f"Updating package list...")
            subprocess.run(f"sudo {package_manager} update -y", shell=True, check=True, capture_output=True)
            logging.info(f"Installing dependencies...")
            try:
                subprocess.run(f"sudo {package_manager} install -y {deps[package_manager]}", shell=True, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                if "Unmet dependencies" in e.stderr.decode():
                    logging.warning(f"Unmet dependencies detected. Attempting to fix with 'apt --fix-broken install'...")
                    subprocess.run(f"sudo {package_manager} --fix-broken install -y", shell=True, check=True, capture_output=True)
                    logging.info(f"Retrying dependency installation...")
                    subprocess.run(f"sudo {package_manager} install -y {deps[package_manager]}", shell=True, check=True, capture_output=True)
                else:
                    raise # Re-raise if it's a different error
        elif package_manager == "yum":
            logging.info(f"Installing dependencies...")
            subprocess.run(f"sudo {package_manager} install -y {deps[package_manager]}", shell=True, check=True, capture_output=True)
        elif package_manager == "pacman":
            logging.info(f"Updating system...")
            subprocess.run(f"sudo {package_manager} -Syu --noconfirm", shell=True, check=True, capture_output=True)
            logging.info(f"Installing dependencies...")
            subprocess.run(f"sudo {package_manager} -S --noconfirm {deps[package_manager]}", shell=True, check=True, capture_output=True)
        elif package_manager == "brew":
            logging.info(f"Updating Homebrew...")
            subprocess.run(f"{package_manager} update", shell=True, check=True, capture_output=True)
            logging.info(f"Installing dependencies...")
            subprocess.run(f"{package_manager} install {deps[package_manager]}", shell=True, check=True, capture_output=True)
        
        logging.info(f"System dependencies installed successfully.\n")

        # Install Poetry if not already present
        if not shutil.which("poetry"):
            logging.info(f"--- Installing Poetry ---")
            try:
                subprocess.run("curl -sSL https://install.python-poetry.org | python3 -", shell=True, check=True, capture_output=True)
                logging.info(f"Poetry installed successfully.\n")
            except subprocess.CalledProcessError as e:
                error_message = f"Error installing Poetry: {e}\nStderr: {e.stderr.decode()}"
                logging.error(error_message)
                logging.error(f"Error installing Poetry: {e}")
                logging.error(f"Stderr: {e.stderr.decode()}")
                return False, False
        else:
            logging.info(f"Poetry is already installed.\n")

        return True, False # Success, installed now
    except subprocess.CalledProcessError as e:
        error_message = f"Error installing dependencies: {e}\nStderr: {e.stderr.decode()}"
        logging.error(error_message)
        logging.error(f"Error installing dependencies: {e}")
        logging.error(f"Stderr: {e.stderr.decode()}")
        return False, False

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
        logging.info(f"Go environment variables added/updated in {shell_config_path}.")
        return True
    else:
        logging.warning(f"Go environment variables already present in {shell_config_path}. No changes made.")
        return False

def install_go():
    if shutil.which("go"):
        logging.info(f"Go is already installed.\n")
        return True

    logging.info(f"Installing Go...")
    try:
        try:
            version_url = "https://go.dev/VERSION?m=text"
            version_res = subprocess.run(["curl", "-s", version_url], capture_output=True, text=True, check=True)
            version = version_res.stdout.splitlines()[0].strip()
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.warning(f"Could not fetch latest Go version ({e}). Falling back to a default version.")
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
            logging.error(f"Unsupported architecture: {arch}. Please install Go manually.")
            return False

        go_url = f"https://dl.google.com/go/{version}.{os_name}-{arch}.tar.gz"
        go_tar_path = "/tmp/go.tar.gz"
        checksum_url = f"{go_url}.sha256"

        logging.info(f"Downloading Go {version}...\n")
        subprocess.run(["wget", go_url, "-O", go_tar_path], check=True, capture_output=True)

        logging.info(f"Verifying checksum...\n")
        try:
            checksum_res = subprocess.run(["curl", "-s", checksum_url], capture_output=True, text=True, check=True)
            expected_checksum = checksum_res.stdout.strip()
            
            sha256_hash = hashlib.sha256()
            with open(go_tar_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            calculated_checksum = sha256_hash.hexdigest()

            if expected_checksum != calculated_checksum:
                logging.error(f"Checksum verification failed. The downloaded file may be corrupted.")
                os.remove(go_tar_path)
                return False
            logging.info(f"Checksum verified successfully.\n")

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.warning(f"Could not verify checksum ({e}). Proceeding with installation at your own risk.\n")

        logging.info(f"Installing Go...\n")
        go_install_dir = os.path.join(os.environ["HOME"], ".huntools", "go")
        
        # Remove old Go installation from the user-specific path (if any)
        # This should happen BEFORE creating the directory for the new installation
        subprocess.run(["rm", "-rf", go_install_dir], check=True, capture_output=True)
        
        os.makedirs(go_install_dir, exist_ok=True) # This creates the directory
        
        # Extract Go into the user-specific path
        subprocess.run(["tar", "-C", go_install_dir, "-xzf", go_tar_path], check=True, capture_output=True)
        os.remove(go_tar_path)

        # After extraction, Go binaries are typically in a 'go' subdirectory within the install_dir
        goroot = os.path.join(go_install_dir, "go")
        gopath = DEFAULT_GO_WORKSPACE_DIR
        
        logging.info(f"Configuring environment variables...\n")
        
        # Update env .bashrc
        _add_go_env_to_shell_config(os.path.join(os.environ["HOME"], ".bashrc"), goroot, gopath)
        
        # Update env .zshrc
        _add_go_env_to_shell_config(os.path.join(os.environ["HOME"], ".zshrc"), goroot, gopath)

        # Update .profile 
        # Note: for systems that use it for non-login shells
        _add_go_env_to_shell_config(os.path.join(os.environ["HOME"], ".profile"), goroot, gopath)

        # Special note for fish shell users
        if "fish" in os.environ.get("SHELL", ""):
            logging.warning(f"Detected fish shell. Please manually add the following to your ~/.config/fish/config.fish:")
            logging.warning(f"  set -x GOROOT {goroot}")
            logging.warning(f"  set -x GOPATH {gopath}")
            logging.warning(f"  fish_add_path $GOPATH/bin $GOROOT/bin")
            logging.warning(f"Then run 'source ~/.config/fish/config.fish' or restart your terminal.\n")

        logging.info(f"Go has been installed successfully.")
        
        # Set environment variables for the current process
        os.environ["GOROOT"] = goroot
        os.environ["GOPATH"] = gopath
        os.environ["PATH"] = f"{gopath}/bin:{goroot}/bin:{os.environ['PATH']}"
        logging.debug(f"GOROOT set to: {os.environ['GOROOT']}")
        logging.debug(f"GOPATH set to: {os.environ['GOPATH']}")
        logging.debug(f"PATH updated to: {os.environ['PATH']}")

        logging.warning(f"Please restart your shell or run 'source ~/.bashrc' to apply the changes.\n")
        return True
        
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        error_message = f"Error installing Go: {e}"
        if isinstance(e, subprocess.CalledProcessError):
            error_message += f"\nStderr: {e.stderr.decode()}"
        logging.error(error_message)
        logging.error(f"Error installing Go: {e}")
        if isinstance(e, subprocess.CalledProcessError):
            logging.error(f"Stderr: {e.stderr.decode()}")
        return False

def _install_tool_worker(tool, tool_info, install_function):
    """Worker function to install a single tool."""
    if tool_info.get("size") == "large":
        response = input(f"{Colors.YELLOW}The tool '{tool}' is large. Do you want to install it? (y/n): {Colors.NC}").lower()
        if response != 'y':
            logging.warning(f"Skipping installation of {tool}.")
            return tool, "skipped"

    existing_path = shutil.which(tool.lower())
    if existing_path:
        logging.info(f"{tool} is already installed at {existing_path}.")
        return tool, "success"

    logging.info(f"Installing {tool}...")
    try:
        install_function(tool)
        logging.info(f"{tool} installed successfully.")
        return tool, "success"
    except subprocess.CalledProcessError as e:
        error_message = f"Error installing {tool}: {e}\nStderr: {e.stderr.decode()}\nSuggestion: Please check the tool's repository for known issues or try manual installation. Command: {e.cmd}"
        logging.error(error_message)
        logging.error(f"Error installing {tool}: {e}")
        logging.warning(f"Suggestion: Please check the tool's repository for known issues or try manual installation. Command: {e.cmd}\n")
        return tool, "failed"
    except Exception as e:
        error_message = f"An unexpected error occurred while installing {tool}: {e}"
        logging.error(error_message)
        logging.error(f"An unexpected error occurred while installing {tool}: {e}")
        return tool, "failed"

def _install_tools(title, tools, install_function):
    logging.info(f"--- {title} ---")
    success_count = 0
    fail_count = 0
    skipped_count = 0

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_tool = {executor.submit(_install_tool_worker, tool, ALL_TOOLS.get(tool, {}), install_function): tool for tool in tools}
        for future in concurrent.futures.as_completed(future_to_tool):
            tool = future_to_tool[future]
            try:
                _, status = future.result()
                if status == "success":
                    success_count += 1
                elif status == "skipped":
                    skipped_count += 1
                else:
                    fail_count += 1
            except Exception as exc:
                logging.error(f'{tool} generated an exception: {exc}')
                fail_count += 1

    logging.info(f"--- {title} summary ---")
    logging.info(f"Successfully installed/skipped: {success_count}")
    logging.warning(f"Skipped: {skipped_count}")
    logging.error(f"Failed to install: {fail_count}\n")

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
        logging.error(f"Unsupported OS for package installation. Please install manually: {' '.join(package_tools)}")
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
    python_git_tools = {name: tool for name, tool in ALL_TOOLS.items() if tool["type"] == "python_git"}
    install_dir = config["PATHS"].get("python_dir", DEFAULT_PYTHON_INSTALL_DIR)
    os.makedirs(install_dir, exist_ok=True)
    git_success_count = 0
    git_fail_count = 0

    logging.info(f"--- Installing Python tools from Git ---")

    for tool_name, tool_info in python_git_tools.items():
        if tool_info.get("size") == "large":
            response = input(f"{Colors.YELLOW}The tool '{tool_name}' is large. Do you want to install it? (y/n): {Colors.NC}").lower()
            if response != 'y':
                logging.warning(f"Skipping installation of {tool_name}.")
                continue

        logging.info(f"Installing {tool_name} from git...")
        repo_path = os.path.join(install_dir, tool_name)
        if os.path.exists(repo_path):
            if not os.path.exists(os.path.join(repo_path, ".git")):
                logging.warning(f"Incomplete installation of {tool_name} found. Removing and reinstalling...")
                shutil.rmtree(repo_path)
            else:
                repo_path = os.path.join(install_dir, tool_name)
                logging.info(f"{tool_name} is already installed at {repo_path}.")
                git_success_count += 1
                continue
        try:
            subprocess.run(["git", "clone", tool_info["url"], repo_path], check=True, capture_output=True)
            logging.info(f"{tool_name} cloned successfully.")

            if os.path.exists(os.path.join(repo_path, "poetry.lock")):
                logging.info(f"Installing dependencies with poetry...")
                subprocess.run(["poetry", "install"], cwd=repo_path, check=True, capture_output=True)
                logging.info(f"Dependencies installed successfully.")

            git_success_count += 1

        except subprocess.CalledProcessError as e:
            error_message = f"Error installing {tool_name}: {e}\nStderr: {e.stderr.decode()}"
            logging.error(error_message)
            logging.error(f"Error installing {tool_name}: {e}")
            logging.error(f"Stderr: {e.stderr.decode()}")
            git_fail_count += 1

    # Pip tools
    pip_tools = [name for name, tool in ALL_TOOLS.items() if tool["type"] == "pip"]
    def _install_pip_tool(tool):
        subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", tool], check=True, capture_output=True)
    
    pip_install_success = _install_tools("Installing Python tools from Pip", pip_tools, _install_pip_tool)
    
    logging.info(f"--- Python tools installation summary ---")
    logging.info(f"Successfully installed from Git: {git_success_count}")
    logging.error(f"Failed to install from Git: {git_fail_count}")

    return git_fail_count == 0 and pip_install_success


def install_git_repos():
    logging.info(f"--- Cloning other git repositories ---")
    git_repos = {name: tool["url"] for name, tool in ALL_TOOLS.items() if tool["type"] == "git"}
    install_dir = config["PATHS"].get("git_dir", DEFAULT_GIT_INSTALL_DIR)
    os.makedirs(install_dir, exist_ok=True)
    success_count = 0
    fail_count = 0

    for repo_name, repo_url in git_repos.items():
        logging.info(f"Cloning {repo_name}...")
        repo_path = os.path.join(install_dir, repo_name)
        if os.path.exists(repo_path):
            if not os.path.exists(os.path.join(repo_path, ".git")):
                logging.warning(f"Incomplete installation of {repo_name} found. Removing and reinstalling...")
                shutil.rmtree(repo_path)
            else:
                logging.info(f"{repo_name} is already cloned.")
                success_count += 1
                continue
        try:

            subprocess.run(["git", "clone", repo_url, repo_path], check=True, capture_output=True)
            logging.info(f"{repo_name} cloned successfully.")
            success_count += 1
        except subprocess.CalledProcessError as e:
            error_message = f"Error cloning {repo_name}: {e}\nStderr: {e.stderr.decode()}"
            logging.error(error_message)
            logging.error(f"Error cloning {repo_name}: {e}")
            logging.error(f"Stderr: {e.stderr.decode()}")
            fail_count += 1

    logging.info(f"--- Git repositories cloning summary ---")
    logging.info(f"Successfully cloned: {success_count}")
    logging.error(f"Failed to clone: {fail_count}\n")

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
    logging.info(f"--- Installing huntools to the system ---")
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
                logging.info(f"huntools installed/updated successfully to {destination_path}.")
            else:
                logging.error(f"Error installing/updating huntools.")
                if process.stderr:
                    logging.error(f"Stderr: {process.stderr.decode()}")
        else:
            logging.info(f"huntools is already up-to-date.")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

def install_all():
    logging.info(f"===========================================")
    logging.info(f"--- Starting Full Installation of Huntools ---")
    logging.info(f"===========================================\n")

    dependencies_status = False
    go_status = False
    go_tools_status = False
    packages_status = False
    python_tools_status = False
    git_repos_status = False

    deps_success, deps_already_installed = install_dependencies()
    if deps_success:
        dependencies_status = True
        if deps_already_installed:
            logging.info(f"--- Step 1/6: System Dependencies Already Installed ---\n")
        else:
            logging.info(f"--- Step 1/6: Installing System Dependencies ---\n")
    else:
        logging.error(f"Installation aborted due to an error during dependency installation.")
        logging.error(f"--- Step 1/6: System Dependencies Installation Failed ---\n")

    go_success, go_already_installed = install_go()
    if go_success:
        go_status = True
        if go_already_installed:
            logging.info(f"--- Step 2/6: Go Already Installed ---\n")
        else:
            logging.info(f"--- Step 2/6: Installing Go ---\n")
    else:
        logging.error(f"Installation aborted due to an error during Go installation.")
        logging.error(f"--- Step 2/6: Go Installation Failed ---\n")

    logging.info(f"--- Step 3/6: Installing Go Tools ---")
    if install_go_tools():
        go_tools_status = True
        logging.info(f"--- Step 3/6: Go Tools Installation Attempted ---\n")
    else:
        logging.warning(f"Some Go tools failed to install. Continuing with the rest of the installation...")
        logging.error(f"--- Step 3/6: Go Tools Installation Failed ---\n")

    logging.info(f"--- Step 4/6: Installing System Packages ---")
    if install_packages():
        packages_status = True
        logging.info(f"--- Step 4/6: System Packages Installation Attempted ---\n")
    else:
        logging.warning(f"Some packages failed to install. Continuing with the rest of the installation...")
        logging.error(f"--- Step 4/6: System Packages Installation Failed ---\n")

    logging.info(f"--- Step 5/6: Installing Python Tools ---")
    if install_python_tools():
        python_tools_status = True
        logging.info(f"--- Step 5/6: Python Tools Installation Attempted ---\n")
    else:
        logging.warning(f"Some Python tools failed to install. Continuing with the rest of the installation...")
        logging.error(f"--- Step 5/6: Python Tools Installation Failed ---\n")

    logging.info(f"--- Step 6/6: Cloning Git Repositories ---")
    if install_git_repos():
        git_repos_status = True
        logging.info(f"--- Step 6/6: Git Repositories Cloning Attempted ---\n")
    else:
        logging.warning(f"Some Git repositories failed to clone. Continuing with the rest of the installation...")
        logging.error(f"--- Step 6/6: Git Repositories Cloning Failed ---\n")

    logging.info(f"=====================================")
    logging.info(f"--- Huntools installation complete! ---")
    logging.info(f"=====================================")

    # Summary Log
    summary_log = []
    summary_log.append(f"\n--- Installation Summary ---")
    if dependencies_status:
        summary_log.append(f"System Dependencies: SUCCESS")
    else:
        summary_log.append(f"System Dependencies: FAILED (Manual intervention may be required)")

    if go_status:
        summary_log.append(f"Go Installation: SUCCESS")
    else:
        summary_log.append(f"Go Installation: FAILED (Manual intervention may be required)")

    if go_tools_status:
        summary_log.append(f"Go Tools: SUCCESS")
    else:
        summary_log.append(f"Go Tools: PARTIAL/FAILED (Check logs for details)")

    if packages_status:
        summary_log.append(f"System Packages: SUCCESS")
    else:
        summary_log.append(f"System Packages: PARTIAL/FAILED (Check logs for details)")

    if python_tools_status:
        summary_log.append(f"Python Tools: SUCCESS")
    else:
        summary_log.append(f"Python Tools: PARTIAL/FAILED (Check logs for details)")

    if git_repos_status:
        summary_log.append(f"Git Repositories: SUCCESS")
    else:
        summary_log.append(f"Git Repositories: PARTIAL/FAILED (Check logs for details)")

    summary_log.append(f"=====================================")

    # Print summary to console
    for line in summary_log:
        logging.info(line)

    # Write summary to logs.txt
    with open("logs.txt", "w") as f:
        # Remove ANSI escape codes for the log file
        clean_summary = [re.sub(r'\x1b\[([0-9]{1,2};)?([0-9]{1,2})?m', '', line) for line in summary_log]
        f.write("\n".join(clean_summary))
    
    # Also log the summary to errors.log for comprehensive error reporting
    logging.error("\n".join(clean_summary))

    logging.info(f"Installation summary written to logs.txt")

def install_single(tool_name):
    install_multiple(tool_name)

def install_multiple(tools_str):
    logging.info(f"--- Installing multiple tools ---")
    
    # Ensure system dependencies are installed first
    deps_success, deps_already_installed = install_dependencies()
    if not deps_success:
        logging.error(f"System dependency installation failed. Aborting tool installation.")
        return
    if not deps_already_installed:
        logging.info(f"--- 🔧 Installing system dependencies ---")

    tool_names = [tool.strip() for tool in tools_str.split(',')]

    # Check if any Go tools are being installed and install Go if necessary
    needs_go_installation = False
    for tool_name in tool_names:
        tool_name_lower = tool_name.lower()
        if tool_name_lower in ALL_TOOLS_LOWER_MAP:
            actual_tool_name = ALL_TOOLS_LOWER_MAP[tool_name_lower]
            if ALL_TOOLS[actual_tool_name]["type"] == "go":
                needs_go_installation = True
                break
    
    if needs_go_installation:
        go_success, go_already_installed = install_go()
        if not go_success:
            logging.error(f"Go installation failed. Aborting Go tool installation.")
            # Filter out Go tools from the list if Go installation failed
            tool_names = [name for name in tool_names if ALL_TOOLS.get(ALL_TOOLS_LOWER_MAP.get(name.lower()), {}).get("type") != "go"]
            if not tool_names: # If only Go tools were requested and Go installation failed
                return
        if not go_already_installed:
            logging.info(f"--- Checking and Installing Go ---")


    def _install_worker(tool_name):
        tool_name_lower = tool_name.lower()
        if tool_name_lower not in ALL_TOOLS_LOWER_MAP:
            logging.error(f"Error: Tool '{tool_name}' not found.")
            return

        actual_tool_name = ALL_TOOLS_LOWER_MAP[tool_name_lower]
        tool = ALL_TOOLS[actual_tool_name]
        tool_type = tool["type"]

        if tool_type == "go":
            subprocess.run(tool["install"], shell=True, check=True, capture_output=True)
        elif tool_type == "package":
            package_manager = get_package_manager()
            if not package_manager:
                raise Exception(f"Unsupported OS for package installation of {actual_tool_name}")
            if package_manager == "apt-get":
                subprocess.run(f"sudo {package_manager} install -y {actual_tool_name}", shell=True, check=True, capture_output=True)
            elif package_manager == "yum":
                subprocess.run(f"sudo {package_manager} install -y {actual_tool_name}", shell=True, check=True, capture_output=True)
            elif package_manager == "pacman":
                subprocess.run(f"sudo {package_manager} -S --noconfirm {actual_tool_name}", shell=True, check=True, capture_output=True)
            elif package_manager == "brew":
                subprocess.run(f"{package_manager} install {actual_tool_name}", shell=True, check=True, capture_output=True)
        elif tool_type == "python_git":
            install_dir = os.path.join(os.environ["HOME"], ".huntools", "python")
            os.makedirs(install_dir, exist_ok=True)
            repo_url = tool["url"]
            repo_path = os.path.join(install_dir, actual_tool_name)
            subprocess.run(["git", "clone", repo_url, repo_path], check=True, capture_output=True)
        elif tool_type == "pip":
            subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", tool["install"]], check=True, capture_output=True)
        elif tool_type == "git":
            install_dir = config["PATHS"].get("git_dir", DEFAULT_GIT_INSTALL_DIR)
            repo_url = tool["url"]
            repo_path = os.path.join(install_dir, actual_tool_name)
            subprocess.run(["git", "clone", repo_url, repo_path], check=True, capture_output=True)

    _install_tools("Installing tools", tool_names, _install_worker)


def reinstall_single(tool_name, force=False):
    logging.info(f"--- Reinstalling {tool_name} ---")

    tool_name_lower = tool_name.lower()
    if tool_name_lower not in ALL_TOOLS_LOWER_MAP:
        logging.error(f"Error: Tool '{tool_name}' not found.")
        logging.warning(f"run 'huntools display --all' to see the list of available tools.\n")
        return

    actual_tool_name = ALL_TOOLS_LOWER_MAP[tool_name_lower]
    remove_single(actual_tool_name, force)
    install_single(actual_tool_name)
    logging.info(f"--- Reinstallation of {actual_tool_name} complete! ---")

def display_all(output_format="text"):
    if output_format == "json":
        print(json.dumps(ALL_TOOLS, indent=4))
        return

    logging.info(f"Available tools:")
    all_tools = sorted(ALL_TOOLS.keys(), key=str.lower)
    if not all_tools:
        logging.warning(f"  No tools available.")
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
    logging.info(f"Performing health check on all tools...")
    all_tool_names = sorted(ALL_TOOLS.keys())
    installed_count = 0
    total_tools = len(all_tool_names)

    for tool_name in all_tool_names:
        tool = ALL_TOOLS[tool_name]
        tool_type = tool["type"]
        
        is_installed = False
        
        tool_path = shutil.which(tool_name) or shutil.which(tool_name.lower())
        if tool_path:
            logging.info(f"  - {tool_name}: Installed (at {tool_path})")
            is_installed = True
        
        elif tool_type == "python_git":
            repo_path = os.path.join(config["PATHS"].get("python_dir", DEFAULT_PYTHON_INSTALL_DIR), tool_name)
            if os.path.exists(repo_path):
                logging.info(f"  - {tool_name}: Installed (Python Git Repo) (at {repo_path})")
                is_installed = True
        
        elif tool_type == "git":
            repo_path = os.path.join(config["PATHS"].get("git_dir", DEFAULT_GIT_INSTALL_DIR), tool_name)
            if os.path.exists(repo_path):
                logging.info(f"  - {tool_name}: Installed (Git Repo) (at {repo_path})")
                is_installed = True
        elif tool_type == "go":
            go_bin_dir = config["PATHS"].get("go_bin_dir", DEFAULT_GO_BIN_DIR)
            huntools_go_bin_dir = os.path.join(os.environ["HOME"], ".huntools", "go")
            if os.path.exists(os.path.join(go_bin_dir, tool_name.lower())):
                logging.info(f"  - {tool_name}: Installed (at {os.path.join(go_bin_dir, tool_name.lower())})")
                is_installed = True
            elif os.path.exists(os.path.join(huntools_go_bin_dir, tool_name.lower())):
                logging.info(f"  - {tool_name}: Installed (at {os.path.join(huntools_go_bin_dir, tool_name.lower())})")
                is_installed = True

        if is_installed:
            installed_count += 1
        else:
            logging.error(f"  - {tool_name}: Not Found")
    
    logging.info(f"Summary: {installed_count}/{total_tools} tools installed.")

def update_single(tool_name):
    logging.info(f"Updating single tool: {tool_name}")

    if tool_name not in ALL_TOOLS:
        logging.error(f"Error: Tool '{tool_name}' not found.")
        logging.warning(f"run 'huntools display --all' to see the list of available tools.\n")
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
            logging.warning(f"Tool {tool_name} not found in {repo_path}. Cannot update.")

    elif tool_type == "git":
        repo_path = os.path.join(os.environ["HOME"], ".huntools", "git", tool_name)
        if os.path.exists(repo_path):
            subprocess.run(["git", "-C", repo_path, "pull"])
        else:
            logging.warning(f"Tool {tool_name} not found in {repo_path}. Cannot update.")

    elif tool_type == "package":
        package_manager = get_package_manager()
        if package_manager == "apt-get":
            subprocess.run(f"sudo {package_manager} install --only-upgrade -y {tool_name}", shell=True)
        elif package_manager == "yum":
            subprocess.run(f"sudo {package_manager} update -y {tool_name}", shell=True)
        elif package_manager == "pacman":
            logging.warning(f"For Arch Linux, please run 'sudo pacman -Syu' to update all packages.")
        elif package_manager == "brew":
            subprocess.run(f"brew upgrade {tool_name}", shell=True)
def update_all():
    logging.info(f"--- Updating all tools ---")
    
    package_manager = get_package_manager()
    package_tools = [name for name, tool in ALL_TOOLS.items() if tool["type"] == "package"]

    if package_manager and package_tools:
        logging.info(f"Updating system packages via {package_manager}...")
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
                 logging.warning(f"For Arch Linux, all packages are updated together. Running full system upgrade...")
                 command = f"sudo {package_manager} -Syu --noconfirm"
                 subprocess.run(command, shell=True, check=True, capture_output=True)

            elif package_manager == "brew":
                command = f"brew upgrade {' '.join(package_tools)}"
                subprocess.run(command, shell=True, check=True, capture_output=True)

            logging.info(f"System packages updated.\n")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error updating system packages: {e}")
            logging.error(f"Stderr: {e.stderr.decode()}")
            logging.warning(f"Continuing with other tool updates...\n")
    else:
        logging.warning(f"No system packages to update or package manager not supported.\n")

    for tool_name, tool_info in ALL_TOOLS.items():
        if tool_info["type"] == "package":
            continue 

        logging.info(f"Updating {tool_name}...")
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
                    logging.warning(f"Tool {tool_name} (python_git) not found at {repo_path}. Skipping update.")
                    continue
            elif tool_type == "git":
                repo_path = os.path.join(os.environ["HOME"], ".huntools", "git", tool_name)
                if os.path.exists(repo_path):
                    subprocess.run(["git", "-C", repo_path, "pull"], check=True, capture_output=True)
                else:
                    logging.warning(f"Tool {tool_name} (git) not found at {repo_path}. Skipping update.")
                    continue
            
            logging.info(f"{tool_name} updated successfully.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error updating {tool_name}: {e}")
            logging.error(f"Stderr: {e.stderr.decode()}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while updating {tool_name}: {e}")
    
    logging.info(f"--- All tools update process completed ---")

def get_tool_location_and_command(tool_name, tool_info):
    tool_type = tool_info["type"]
    tool_location = "Unknown"
    removal_command = None
    needs_sudo = False

    if tool_type == "go":
        gopath_bin = os.path.join(config["PATHS"].get("go_bin_dir", DEFAULT_GO_BIN_DIR), tool_name.lower())
        if os.path.exists(gopath_bin):
            tool_location = gopath_bin
            removal_command = ["rm", gopath_bin]
        else:
            tool_path = shutil.which(tool_name.lower())
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
    logging.info(f"Removing single tool: {tool_name}")

    tool_name_lower = tool_name.lower()
    if tool_name_lower not in ALL_TOOLS_LOWER_MAP:
        logging.error(f"Error: Tool '{tool_name}' not found.")
        logging.warning(f"run 'huntools display --all' to see the list of available tools.\n")
        return

    actual_tool_name = ALL_TOOLS_LOWER_MAP[tool_name_lower]
    tool_info = ALL_TOOLS[actual_tool_name]

    if not _is_tool_installed(actual_tool_name, tool_info):
        logging.warning(f"Tool '{tool_name}' is not currently installed. Skipping removal.\n")
        return
    
    tool_location, removal_command, needs_sudo = get_tool_location_and_command(actual_tool_name, tool_info)

    if not force:
        if tool_location == "Unknown" or (tool_info["type"] in ["python_git", "git"] and not os.path.exists(tool_location)):
            logging.warning(f"⚠️  Warning: Could not determine the exact installation path for {tool_name}. Proceeding with generic removal attempt.")

        logging.warning(f"⚠️  WARNING: You are about to remove {tool_name}.")
        logging.warning(f"📍 Location: {tool_location}")
        if needs_sudo:
            logging.warning(f"🚨 This tool is in a system-protected directory and may require 'sudo'.")

        confirmation = input(f"{Colors.YELLOW}Are you sure you want to proceed? (yes/no): {Colors.NC}").lower()
        if confirmation != 'yes':
            logging.info(f"Removal of {tool_name} aborted.")
            return
    else:
        logging.info(f"Force removal of {tool_name} initiated.")

    tool_type = tool_info["type"]
    try:
        if tool_type == "go":
            go_bin_dir = config["PATHS"].get("go_bin_dir", os.path.join(os.environ["HOME"], "go", "bin"))
            go_tool_path = os.path.join(go_bin_dir, tool_name.lower())

            if os.path.exists(go_tool_path):
                try:
                    os.remove(go_tool_path)
                    logging.info(f"Removed {tool_name} from {go_tool_path}.")
                except OSError as e:
                    logging.error(f"Error removing {tool_name} from {go_tool_path}: {e}")
                    logging.warning(f"If this is a permission error, try running with 'sudo'.")
            else:
                tool_path_from_which = shutil.which(tool_name.lower())
                if tool_path_from_which:
                    try:
                        os.remove(tool_path_from_which)
                        logging.info(f"Removed {tool_name} from {tool_path_from_which}.")
                    except OSError as e:
                        logging.error(f"Error removing {tool_name} from {tool_path_from_which}: {e}")
                        logging.warning(f"If this is a permission error, try running with 'sudo'.")
                else:
                    logging.error(f"Error: {tool_name} not found in configured Go binary directory ({go_bin_dir}) or system PATH for removal.")

        elif tool_type == "pip":
            subprocess.run(removal_command, check=True)
            logging.info(f"Removed {tool_name} via pip.")

        elif tool_type == "python_git" or tool_type == "git":
            if os.path.exists(tool_location): 
                shutil.rmtree(tool_location)
                logging.info(f"Removed {tool_name} repository from {tool_location}.")
            else:
                logging.error(f"Error: Repository for {tool_name} not found at {tool_location} for removal.")

        elif tool_type == "package":
            if removal_command:
                subprocess.run(removal_command, check=True)
                logging.info(f"Removed {tool_name} via package manager.")
            else:
                logging.error(f"Error: Could not find package manager removal command for {tool_name}.")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error removing {tool_name}: {e}")
        if e.stderr:
            logging.error(f"Stderr: {e.stderr.decode()}")
        logging.warning(f"If this is a permission error, try running with 'sudo'.")
    except OSError as e:
        logging.error(f"Error removing {tool_name}: {e}")
        logging.warning(f"If this is a permission error, try running with 'sudo'.")

        
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
    logging.warning(f"⚠️  WARNING: You are about to remove {installed_tool_count} currently installed huntools. This action is irreversible.")
    if not force:
        confirmation = input(f"{Colors.YELLOW}Are you sure you want to proceed? (yes/no): {Colors.NC}").lower()
        if confirmation != 'yes':
            logging.info(f"Removal aborted.")
            return

    logging.info(f"--- Removing all installed tools ---")
    
    for tool_name in list(ALL_TOOLS.keys()): 
        remove_single(tool_name)

    huntools_dir = config["PATHS"].get("install_dir", DEFAULT_HUNTOOLS_INSTALL_DIR)
    if os.path.exists(huntools_dir):
        logging.info(f"Removing huntools installation directory: {huntools_dir}")
        try:
            shutil.rmtree(huntools_dir)
            logging.info(f"Removed {huntools_dir}.")
        except OSError as e:
            logging.error(f"Error removing {huntools_dir}: {e}")
            logging.warning(f"If this is a permission error, try running with 'sudo'.")

    logging.info(f"--- All tools removal process completed ---")
    logging.warning(f"Note: Some system packages might require manual removal if not fully uninstalled by individual tool removal.")

def clean_all(force=False):
    logging.warning(f"⚠️  WARNING: You are about to purge delete all data, including configuration. This action is irreversible.")
    if not force:
        confirmation = input(f"{Colors.YELLOW}Are you sure you want to proceed? (yes/no): {Colors.NC}").lower()
        if confirmation != 'yes':
            logging.info(f"Purge aborted.")
            return

    logging.info(f"Purging all huntools data...")
    remove_all()
    config_dir_to_remove = config["PATHS"].get("config_file", CONFIG_DIR)
    if os.path.exists(config_dir_to_remove):
        shutil.rmtree(config_dir_to_remove)
    
    huntools_system_path = "/usr/local/bin/huntools"
    if os.path.exists(huntools_system_path):
        logging.info(f"Removing system-wide huntools executable...")
        try:
            command = f"sudo rm {huntools_system_path}"
            logging.info(f"Running command: {command}")
            process = subprocess.run(command, shell=True, check=False, capture_output=True)
            if process.returncode == 0:
                logging.info(f"Removed {huntools_system_path}.")
            else:
                logging.error(f"Error removing {huntools_system_path}.")
                if process.stderr:
                    logging.error(f"Stderr: {process.stderr.decode()}")
                logging.warning(f"You may need to remove it manually: sudo rm {huntools_system_path}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")

    logging.info(f"All huntools data has been removed.")

def self_update():
    logging.info(f"Updating huntools...")
    
    git_repo_path = config.get("PATHS", {}).get("git_repo_path")
    if not git_repo_path or not os.path.exists(os.path.join(git_repo_path, ".git")):
        logging.error(f"Huntools git repository path not found or invalid.")
        logging.warning(f"Please run the system-wide installation again from within the git repository to set the path:")
        logging.warning(f"  ./huntools.py install -is")
        return

    try:
        logging.info(f"Pulling latest changes from git...")
        subprocess.run(["git", "-C", git_repo_path, "pull"], check=True)
        logging.info(f"huntools updated successfully from git.")

        install_dir = get_install_path()
        destination_path = os.path.join(install_dir, "huntools")

        if os.path.exists(destination_path):
            logging.info(f"System-wide installation detected. Updating executable...")
            try:
                huntools_local_path = os.path.join(git_repo_path, "huntools.py")
                command = f"sudo cp {huntools_local_path} {destination_path} && sudo chmod +x {destination_path}"
                
                logging.info(f"Running command: {command}")
                
                process = subprocess.run(command, shell=True, check=False, capture_output=True)
                
                if process.returncode == 0:
                    logging.info(f"System-wide executable updated successfully to {destination_path}.")
                else:
                    logging.error(f"Error updating system-wide executable.")
                    if process.stderr:
                        logging.error(f"Stderr: {process.stderr.decode()}")
                    logging.warning(f"You may need to run 'sudo ./huntools.py install -is' again manually.")
            
            except Exception as e:
                logging.error(f"An unexpected error occurred while updating the system-wide executable: {e}")

    except subprocess.CalledProcessError:
        logging.error(f"Update failed. Please make sure you are in the huntools git repository.")

def show_path():
    logging.info(f"Displaying huntools paths:")
    install_dir = config["PATHS"].get("install_dir", DEFAULT_HUNTOOLS_INSTALL_DIR)
    python_dir = config["PATHS"].get("python_dir", DEFAULT_PYTHON_INSTALL_DIR)
    git_dir = config["PATHS"].get("git_dir", DEFAULT_GIT_INSTALL_DIR)
    go_bin_dir = config["PATHS"].get("go_bin_dir", DEFAULT_GO_BIN_DIR)
    config_file_path = config["PATHS"].get("config_file", os.path.join(CONFIG_DIR, "config.yml"))

    logging.info(f"  - Installation directory: {install_dir}")
    logging.info(f"  - Python tools directory: {python_dir}")
    logging.info(f"  - Git repos directory: {git_dir}")
    logging.info(f"  - Go binary path: {go_bin_dir}")
    logging.info(f"  - Config file: {config_file_path}")

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
        logging.error(f"Failed to fetch changelog from URL: {e}")

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
            logging.info(f"Dockerfile successfully generated: {os.path.abspath(filename)}")
        except IOError as e:
            logging.error(f"Error writing Dockerfile to {filename}: {e}")
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
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
        parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output.")

        subparsers = parser.add_subparsers(dest="command", title="Available commands", metavar=" ")

        # Install command
        install_parser = subparsers.add_parser("install", help="Install tools", add_help=False, formatter_class=CustomHelpFormatter)
        install_parser.add_argument("-v", "--verbose", action="store_true", help=argparse.SUPPRESS)
        install_parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
        install_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        install_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        install_parser.add_argument("-s", dest="install_single", help="Install a single, specified tool from the available list.", metavar="TOOL")
        install_parser.add_argument("-m", dest="install_multiple", help="Install multiple tools, separated by commas.", metavar="TOOL1,TOOL2,...")
        install_parser.add_argument("--single", dest="install_single", help=argparse.SUPPRESS, metavar="TOOL")
        install_parser.add_argument("-a", dest="install_all", action="store_true", help="Install all available tools.")
        install_parser.add_argument("--all", dest="install_all", action="store_true", help=argparse.SUPPRESS)
        install_parser.add_argument("-is", dest="install_system", action="store_true", help="Install huntools itself to the system (e.g., /usr/local/bin).")
        install_parser.add_argument("--install-system", dest="install_system", action="store_true", help=argparse.SUPPRESS)

        # Reinstall command
        reinstall_parser = subparsers.add_parser("reinstall", help="Reinstall a tool", add_help=False, formatter_class=CustomHelpFormatter)
        reinstall_parser.add_argument("-v", "--verbose", action="store_true", help=argparse.SUPPRESS)
        reinstall_parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
        reinstall_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        reinstall_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        reinstall_parser.add_argument("tool_name", help="The name of the tool to reinstall")
        reinstall_parser.add_argument("-f", "--force", dest="force_remove", action="store_true", help="Bypass confirmation prompts for removal actions.")

        # Update command
        update_parser = subparsers.add_parser("update", help="Update tools", add_help=False, formatter_class=CustomHelpFormatter)
        update_parser.add_argument("-v", "--verbose", action="store_true", help=argparse.SUPPRESS)
        update_parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
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
        remove_parser.add_argument("-v", "--verbose", action="store_true", help=argparse.SUPPRESS)
        remove_parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
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
        display_parser.add_argument("-v", "--verbose", action="store_true", help=argparse.SUPPRESS)
        display_parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
        display_parser.add_argument("-a", dest="display_all", action="store_true", help="Show all tools available for installation.")
        display_parser.add_argument("--all", dest="display_all", action="store_true", help=argparse.SUPPRESS)
        display_parser.add_argument("-f", "--format", dest="output_format", default="text", help="Specify the output format (text or json).")
        display_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        display_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        
        check_parser = subparsers.add_parser("check", help="Check tool health", add_help=False, formatter_class=CustomHelpFormatter)
        check_parser.add_argument("-v", "--verbose", action="store_true", help=argparse.SUPPRESS)
        check_parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
        check_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        check_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        check_parser.add_argument("-hc", dest="checking_health", action="store_true", help="Perform a health check on all installed tools.")

        show_parser = subparsers.add_parser("show", help="Show information", add_help=False, formatter_class=CustomHelpFormatter)
        show_parser.add_argument("-v", "--verbose", action="store_true", help=argparse.SUPPRESS)
        show_parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
        show_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        show_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        show_parser.add_argument("-pl", dest="path", action="store_true", help="Display all relevant paths used by huntools.")
        show_parser.add_argument("--path", action="store_true", help=argparse.SUPPRESS)
        show_parser.add_argument("-cl", dest="changelog", action="store_true", help="View the latest changes and updates to huntools.")
        show_parser.add_argument("--changelog", action="store_true", help=argparse.SUPPRESS)

        config_parser = subparsers.add_parser("config", help="Configure huntools", add_help=False, formatter_class=CustomHelpFormatter)
        config_parser.add_argument("-v", "--verbose", action="store_true", help=argparse.SUPPRESS)
        config_parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
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
        docker_parser.add_argument("-v", "--verbose", action="store_true", help=argparse.SUPPRESS)
        docker_parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
        docker_parser.add_argument("-h", action="help", help=argparse.SUPPRESS)
        docker_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        docker_parser.add_argument("-g", "--generate", action="store_true", help="Generate a Dockerfile for Huntools.")
        docker_parser.add_argument("-s", dest="save_filename", nargs='?', const="Dockerfile", help="Specify a filename to save the Dockerfile. Defaults to 'Dockerfile'.", metavar="FILENAME")
        docker_parser.add_argument("--save", dest="save_filename", nargs='?', const="Dockerfile", help=argparse.SUPPRESS, metavar="FILENAME")

        args = parser.parse_args()

        setup_logging(args.verbose, args.debug)

        if not args.command:
            parser.print_help()
            sys.exit(1)

        # Manual validation for --format option
        if hasattr(args, 'output_format') and args.output_format not in ["text", "json"]:
            logging.error(f"Error: Invalid output format '{args.output_format}'. Choose from 'text' or 'json'.")
            sys.exit(1)

        if args.command == "install":
            if args.install_all:
                install_all()
            elif args.install_single:
                install_single(args.install_single)
            elif args.install_multiple:
                install_multiple(args.install_multiple)
            elif args.install_system:
                install_system()
            else:
                install_parser.print_help()
                sys.exit(1)
        elif args.command == "reinstall":
            reinstall_single(args.tool_name, args.force_remove)
        elif args.command == "display":
            if args.display_all:
                display_all(args.output_format)
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
                    logging.info(f"Setting custom config file path to: {args.config_path}")
                if args.binary_path:
                    config["PATHS"]["go_bin_dir"] = args.binary_path
                    logging.info(f"Setting custom Go binary path to: {args.binary_path}")
                if args.install_path:
                    config["PATHS"]["install_dir"] = args.install_path
                    config["PATHS"]["python_dir"] = os.path.join(args.install_path, "python")
                    config["PATHS"]["git_dir"] = os.path.join(args.install_path, "git")
                    logging.info(f"Setting custom install path to: {args.install_path}")
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
        logging.error(f"Installation aborted by user (Ctrl+C).")
        sys.exit(1)

if __name__ == "__main__":
    main()  
