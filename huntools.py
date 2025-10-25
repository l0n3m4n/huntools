#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import shutil
import platform
import configparser
import hashlib



# Colors
class Colors:
    BLUE = '''\033[1;34m'''
    NC = '''\033[0m'''
    GREEN = '''\033[0;32m'''
    RED = '''\033[0;31m'''
    YELLOW = '''\033[0;33m'''
    MAGENTA = '''\033[0;35m'''
    CYAN = '''\033[0;36m'''

def show_banner():
    tool_count = len(ALL_TOOLS)
    banner = f"""

  ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓ ▒█████   ▒█████   ██▓      ██████ 
▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    ▒██    ▒ 
▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    ░ ▓██▄   
░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░      ▒   ██▒
░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒▒██████▒▒
 ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░▒ ▒▓▒ ▒ ░
 ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░░ ░▒  ░ ░
 ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   ░  ░  ░  
 ░  ░  ░   ░              ░              ░ ░      ░ ░      ░  ░      ░  
                                                                        
        Author: l0n3m4n | Version: 2.0.0 | {tool_count} Hunter's Arsenal 
"""
    print(f"{Colors.BLUE}{banner}{Colors.NC}")





# Tool lists
ALL_TOOLS = {
    
    # Go Tools
    "ffuf": {"type": "go", "install": "go install -v github.com/ffuf/ffuf/v2@latest"},
    "feroxbuster": {"type": "go", "install": "go install -v github.com/epi052/feroxbuster@latest"},
    "katana": {"type": "go", "install": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"},
    "subfinder": {"type": "go", "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "assetfinder": {"type": "go", "install": "go install -v github.com/tomnomnom/assetfinder@latest"},
    "aquatone": {"type": "go", "install": "go install -v github.com/michenriksen/aquatone@latest"},
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
    "gitleaks": {"type": "go", "install": "go install -v github.com/gitleaks/gitleaks/v8@latest"},
    "trufflehog": {"type": "go", "install": "go install -v github.com/trufflesecurity/trufflehog/v3@latest"},

    # Package Tools
    "seclists": {"type": "package"},
    "jq": {"type": "package"},
    "flameshot": {"type": "package"},
    "lsd": {"type": "package"},
    "cewl": {"type": "package"},
    "nmap": {"type": "package"},
    "massdns": {"type": "package"},
    "testssl.sh": {"type": "package"},

    # Python Git Tools
    "LinkFinder": {"type": "python_git", "url": "https://github.com/GerbenJavado/LinkFinder.git"},
    "OneForAll": {"type": "python_git", "url": "https://github.com/shmilylty/OneForAll.git"},
    "Sublist3r": {"type": "python_git", "url": "https://github.com/aboul3la/Sublist3r.git"},
    "SubDomainizer": {"type": "python_git", "url": "https://github.com/nsonaniya2010/SubDomainizer.git"},
    "cloud_enum": {"type": "python_git", "url": "https://github.com/initstring/cloud_enum.git"},
    "dorks_hunter": {"type": "python_git", "url": "https://github.com/six2dez/dorks_hunter.git"},
    "Corsy": {"type": "python_git", "url": "https://github.com/s0md3v/Corsy.git"},
    "CMSeeK": {"type": "python_git", "url": "https://github.com/Tuhinshubhra/CMSeeK.git"},
    "fav-up": {"type": "python_git", "url": "https://github.com/pielco11/fav-up.git"},
    "Oralyzer": {"type": "python_git", "url": "https://github.com/r0075h3ll/Oralyzer.git"},
    "JSA": {"type": "python_git", "url": "https://github.com/w9w/JSA.git"},
    "CloudHunter": {"type": "python_git", "url": "https://github.com/belane/CloudHunter.git"},
    "ultimate-nmap-parser": {"type": "python_git", "url": "https://github.com/shifty0g/ultimate-nmap-parser.git"},
    "pydictor": {"type": "python_git", "url": "https://github.com/LandGrey/pydictor.git"},
    "smuggler": {"type": "python_git", "url": "https://github.com/defparam/smuggler.git"},
    "regulator": {"type": "python_git", "url": "https://github.com/cramppet/regulator.git"},
    "nomore403": {"type": "python_git", "url": "https://github.com/devploit/nomore403.git"},
    "SwaggerSpy": {"type": "python_git", "url": "https://github.com/UndeadSec/SwaggerSpy.git"},
    "LeakSearch": {"type": "python_git", "url": "https://github.com/JoelGMSec/LeakSearch.git"},
    "ffufPostprocessing": {"type": "python_git", "url": "https://github.com/Damian89/ffufPostprocessing.git"},
    "Spoofy": {"type": "python_git", "url": "https://github.com/MattKeeley/Spoofy.git"},
    "msftrecon": {"type": "python_git", "url": "https://github.com/Arcanum-Sec/msftrecon.git"},
    "Scopify": {"type": "python_git", "url": "https://github.com/Arcanum-Sec/Scopify.git"},
    "metagoofil": {"type": "python_git", "url": "https://github.com/opsdisk/metagoofil.git"},
    "EmailHarvester": {"type": "python_git", "url": "https://github.com/maldevel/EmailHarvester.git"},
    "reconftw_ai": {"type": "python_git", "url": "https://github.com/six2dez/reconftw_ai.git"},

    # Python Pip Tools
    "censys": {"type": "pip"},
    "shodan": {"type": "pip"},
    "dnsvalidator": {"type": "pip"},
    "interlace": {"type": "pip"},
    "wafw00f": {"type": "pip"},
    "commix": {"type": "pip"},
    "urless": {"type": "pip"},
    "ghauri": {"type": "pip"},
    "xnLinkFinder": {"type": "pip"},
    "xnldorker": {"type": "pip"},
    "porch-pirate": {"type": "pip"},
    "p1radup": {"type": "pip"},
    "subwiz": {"type": "pip"},

    # Git Repos
    "Gf-Patterns": {"type": "git", "url": "https://github.com/1ndianl33t/Gf-Patterns.git"},
    "sus_params": {"type": "git", "url": "https://github.com/g0ldencybersec/sus_params.git"},
}


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
    print(f"{Colors.BLUE}--- Installing system dependencies ---{Colors.NC}")
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
            print("Updating package list...")
            subprocess.run(f"sudo {package_manager} update -y", shell=True, check=True, capture_output=True)
            print("Installing dependencies...")
            subprocess.run(f"sudo {package_manager} install -y {deps[package_manager]}", shell=True, check=True, capture_output=True)
        elif package_manager == "yum":
            print("Installing dependencies...")
            subprocess.run(f"sudo {package_manager} install -y {deps[package_manager]}", shell=True, check=True, capture_output=True)
        elif package_manager == "pacman":
            print("Updating system...")
            subprocess.run(f"sudo {package_manager} -Syu --noconfirm", shell=True, check=True, capture_output=True)
            print("Installing dependencies...")
            subprocess.run(f"sudo {package_manager} -S --noconfirm {deps[package_manager]}", shell=True, check=True, capture_output=True)
        elif package_manager == "brew":
            print("Updating Homebrew...")
            subprocess.run(f"{package_manager} update", shell=True, check=True, capture_output=True)
            print("Installing dependencies...")
            subprocess.run(f"{package_manager} install {deps[package_manager]}", shell=True, check=True, capture_output=True)
        
        print(f"{Colors.GREEN}System dependencies installed successfully.{Colors.NC}\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}Error installing dependencies: {e}{Colors.NC}")
        print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
        return False

def install_go():
    print(f"{Colors.BLUE}--- Checking and Installing Go ---{Colors.NC}")
    if shutil.which("go"):
        print(f"{Colors.GREEN}Go is already installed.{Colors.NC}\n")
        return True

    print("Installing Go...")
    try:
        try:
            version_url = "https://go.dev/VERSION?m=text"
            version_res = subprocess.run(["curl", "-s", version_url], capture_output=True, text=True, check=True)
            version = version_res.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Colors.YELLOW}Could not fetch latest Go version. Using a default version.{Colors.NC}")
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

        print(f"Downloading Go {version}...")
        subprocess.run(["wget", go_url, "-O", go_tar_path], check=True, capture_output=True)

        print("Verifying checksum...")
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
            print(f"{Colors.GREEN}Checksum verified successfully.{Colors.NC}")

        except (subprocess.CalledProcessError, FileNotFoundError, ImportError):
            print(f"{Colors.YELLOW}Could not verify checksum. Proceeding with installation at your own risk.{Colors.NC}")

        print("Installing Go...")
        subprocess.run(["sudo", "rm", "-rf", "/usr/local/go"], check=True, capture_output=True)
        subprocess.run(["sudo", "tar", "-C", "/usr/local", "-xzf", go_tar_path], check=True, capture_output=True)
        os.remove(go_tar_path)

        goroot = "/usr/local/go"
        gopath = os.path.join(os.environ["HOME"], "go")
        
        print("Configuring environment variables...")
        with open(os.path.join(os.environ["HOME"], ".bashrc"), "a") as f:
            f.write("\n# Go environment variables\n")
            f.write(f"export GOROOT={goroot}\n")
            f.write(f"export GOPATH={gopath}\n")
            f.write(f"export PATH=$GOPATH/bin:$GOROOT/bin:$PATH\n")

        print(f"{Colors.GREEN}Go has been installed successfully.{Colors.NC}")
        print(f"{Colors.YELLOW}Please restart your shell or run 'source ~/.bashrc' to apply the changes.{Colors.NC}\n")
        return True
        
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"{Colors.RED}Error installing Go: {e}{Colors.NC}")
        if hasattr(e, 'stderr') and e.stderr:
            print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
        return False

def _install_tools(title, tools, install_function):
    print(f"{Colors.BLUE}--- {title} ---{Colors.NC}")
    success_count = 0
    fail_count = 0

    for tool in tools:
        existing_path = shutil.which(tool)
        if existing_path:
            print(f"{Colors.YELLOW}{tool} is already installed at {existing_path}. Skipping installation.{Colors.NC}")
            success_count += 1
            continue

        print(f"Installing {tool}...")
        try:
            install_function(tool)
            print(f"{Colors.GREEN}{tool} installed successfully.{Colors.NC}")
            success_count += 1
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}Error installing {tool}: {e}{Colors.NC}")
            print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
            fail_count += 1

    print(f"\n{Colors.BLUE}--- {title} summary ---{Colors.NC}")
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
    print(f"{Colors.BLUE}--- Installing Python tools ---{Colors.NC}")
    
    # Git tools
    python_git_tools = {name: tool["url"] for name, tool in ALL_TOOLS.items() if tool["type"] == "python_git"}
    install_dir = os.path.join(os.environ["HOME"], ".huntools", "python")
    os.makedirs(install_dir, exist_ok=True)
    git_success_count = 0
    git_fail_count = 0

    print(f"\n{Colors.BLUE}--- Installing Python tools from Git ---{Colors.NC}")
    for tool_name, repo_url in python_git_tools.items():
        print(f"Installing {tool_name} from git...")
        repo_path = os.path.join(install_dir, tool_name)
        if os.path.exists(repo_path):
            if not os.path.exists(os.path.join(repo_path, ".git")):
                print(f"{Colors.YELLOW}Incomplete installation of {tool_name} found. Removing and reinstalling...{Colors.NC}")
                shutil.rmtree(repo_path)
            else:
                print(f"{Colors.GREEN}{tool_name} is already installed.{Colors.NC}")
                git_success_count += 1
                continue

        try:
            subprocess.run(["git", "clone", repo_url, repo_path], check=True, capture_output=True)
            print(f"{Colors.GREEN}{tool_name} cloned successfully.{Colors.NC}")
            
            requirements_path = os.path.join(repo_path, "requirements.txt")
            if os.path.exists(requirements_path):
                print(f"Installing dependencies for {tool_name}...")
                subprocess.run([sys.executable, "-m", "pip", "install", "-r", requirements_path], check=True, capture_output=True)
                print(f"{Colors.GREEN}Dependencies for {tool_name} installed successfully.{Colors.NC}")
            
            git_success_count += 1
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}Error installing {tool_name}: {e}{Colors.NC}")
            print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
            git_fail_count += 1

    # Pip tools
    pip_tools = [name for name, tool in ALL_TOOLS.items() if tool["type"] == "pip"]
    def _install_pip_tool(tool):
        subprocess.run([sys.executable, "-m", "pip", "install", tool], check=True, capture_output=True)

    pip_install_success = _install_tools("Installing Python tools from Pip", pip_tools, _install_pip_tool)

    print(f"\n{Colors.BLUE}--- Python tools installation summary ---{Colors.NC}")
    print(f"{Colors.GREEN}Successfully installed from Git: {git_success_count}{Colors.NC}")
    print(f"{Colors.RED}Failed to install from Git: {git_fail_count}{Colors.NC}")

    return git_fail_count == 0 and pip_install_success

def install_git_repos():
    print(f"{Colors.BLUE}--- Cloning other git repositories ---{Colors.NC}")
    git_repos = {name: tool["url"] for name, tool in ALL_TOOLS.items() if tool["type"] == "git"}
    install_dir = os.path.join(os.environ["HOME"], ".huntools", "git")
    os.makedirs(install_dir, exist_ok=True)

    success_count = 0
    fail_count = 0

    for repo_name, repo_url in git_repos.items():
        print(f"Cloning {repo_name}...")
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
            print(f"{Colors.RED}Error cloning {repo_name}: {e}{Colors.NC}")
            print(f"{Colors.RED}Stderr: {e.stderr.decode()}{Colors.NC}")
            fail_count += 1

    print(f"\n{Colors.BLUE}--- Git repositories cloning summary ---{Colors.NC}")
    print(f"{Colors.GREEN}Successfully cloned: {success_count}{Colors.NC}")
    print(f"{Colors.RED}Failed to clone: {fail_count}{Colors.NC}\n")

    return fail_count == 0

def install_all():
    print(f"\n{Colors.BLUE}==========================================={Colors.NC}")
    print(f"{Colors.BLUE}--- Starting Full Installation of Huntools ---{Colors.NC}")
    print(f"{Colors.BLUE}==========================================={Colors.NC}\n")

    if not install_dependencies():
        print(f"\n{Colors.RED}Installation aborted due to an error during dependency installation.{Colors.NC}")
        sys.exit(1)

    if not install_go():
        print(f"\n{Colors.RED}Installation aborted due to an error during Go installation.{Colors.NC}")
        sys.exit(1)

    if not install_go_tools():
        print(f"\n{Colors.YELLOW}Some Go tools failed to install. Continuing with the rest of the installation...{Colors.NC}")

    if not install_packages():
        print(f"\n{Colors.YELLOW}Some packages failed to install. Continuing with the rest of the installation...{Colors.NC}")

    if not install_python_tools():
        print(f"\n{Colors.YELLOW}Some Python tools failed to install. Continuing with the rest of the installation...{Colors.NC}")

    if not install_git_repos():
        print(f"\n{Colors.YELLOW}Some Git repositories failed to clone. Continuing with the rest of the installation...{Colors.NC}")

    print(f"\n{Colors.GREEN}====================================={Colors.NC}")
    print(f"{Colors.GREEN}--- Huntools installation complete! ---{Colors.NC}")
    print(f"{Colors.GREEN}====================================={Colors.NC}")

def install_single(tool_name):
    print(f"Attempting to install single tool: {tool_name}")

    if tool_name not in ALL_TOOLS:
        print(f"\n{Colors.RED}Error: Tool '{tool_name}' not found.{Colors.NC}")
        print(f"{Colors.YELLOW}run 'huntools display -a' to see the list of available tools.{Colors.NC}\n")
        return

    existing_path = shutil.which(tool_name)
    if existing_path:
        print(f"{Colors.YELLOW}{tool_name} is already installed at {existing_path}. Skipping installation.{Colors.NC}")
        return

    tool = ALL_TOOLS[tool_name]
    tool_type = tool["type"]

    if tool_type == "go":
        print(f"Installing Go tool: {tool_name}")
        subprocess.run(tool["install"], shell=True)
    
    elif tool_type == "package":
        print(f"Installing package: {tool_name}")
        package_manager = get_package_manager()
        if not package_manager:
            print(f"Unsupported OS for package installation.")
            return
        if package_manager == "apt-get":
            subprocess.run(f"sudo {package_manager} install -y {tool_name}", shell=True)
        elif package_manager == "yum":
            subprocess.run(f"sudo {package_manager} install -y {tool_name}", shell=True)
        elif package_manager == "pacman":
            subprocess.run(f"sudo {package_manager} -S --noconfirm {tool_name}", shell=True)
        elif package_manager == "brew":
            subprocess.run(f"{package_manager} install {tool_name}", shell=True)

    elif tool_type == "python_git":
        print(f"Installing Python tool from git: {tool_name}")
        install_dir = os.path.join(os.environ["HOME"], ".huntools", "python")
        os.makedirs(install_dir, exist_ok=True)
        repo_url = tool["url"]
        repo_path = os.path.join(install_dir, tool_name)
        subprocess.run(["git", "clone", repo_url, repo_path])
        
        requirements_path = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(requirements_path):
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", requirements_path])

    elif tool_type == "pip":
        print(f"Installing Python tool from pip: {tool_name}")
        subprocess.run([sys.executable, "-m", "pip", "install", tool_name])

    elif tool_type == "git":
        print(f"Cloning git repository: {tool_name}")
        install_dir = os.path.join(os.environ["HOME"], ".huntools", "git")
        os.makedirs(install_dir, exist_ok=True)
        repo_url = tool["url"]
        repo_path = os.path.join(install_dir, tool_name)
        subprocess.run(["git", "clone", repo_url, repo_path])

def reinstall_single(tool_name):
    print(f"{Colors.BLUE}--- Reinstalling {tool_name} ---{Colors.NC}")
    remove_single(tool_name)
    install_single(tool_name)
    print(f"\n{Colors.GREEN}--- Reinstallation of {tool_name} complete! ---{Colors.NC}")

def display_all():
    print("Available tools:")
    all_tools = sorted(ALL_TOOLS.keys())
    for tool in all_tools:
        print(f"  - {tool}")

def checking_health():
    print("Performing health check on all tools...")
    all_tool_names = sorted(ALL_TOOLS.keys())
    installed_count = 0
    total_tools = len(all_tool_names)

    for tool_name in all_tool_names:
        tool = ALL_TOOLS[tool_name]
        tool_type = tool["type"]
        
        is_installed = False
        
        # First, check if the tool is in the PATH
        tool_path = shutil.which(tool_name)
        if tool_path:
            print(f"  - {tool_name}: {Colors.GREEN}Installed{Colors.NC} {Colors.YELLOW}(at {tool_path}){Colors.NC}")
            is_installed = True
        
        # If not in PATH, check for git repos
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
    
    print(f"\nSummary: {installed_count}/{total_tools} tools installed.")

def update_single(tool_name):
    print(f"Updating single tool: {tool_name}")

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
            print(f"Tool {tool_name} not found in {repo_path}. Cannot update.")

    elif tool_type == "git":
        repo_path = os.path.join(os.environ["HOME"], ".huntools", "git", tool_name)
        if os.path.exists(repo_path):
            subprocess.run(["git", "-C", repo_path, "pull"])
        else:
            print(f"Tool {tool_name} not found in {repo_path}. Cannot update.")

    elif tool_type == "package":
        package_manager = get_package_manager()
        if package_manager == "apt-get":
            subprocess.run(f"sudo {package_manager} install --only-upgrade -y {tool_name}", shell=True)
        elif package_manager == "yum":
            subprocess.run(f"sudo {package_manager} update -y {tool_name}", shell=True)
        elif package_manager == "pacman":
            print("For Arch Linux, please run 'sudo pacman -Syu' to update all packages.")
        elif package_manager == "brew":
            subprocess.run(f"brew upgrade {tool_name}", shell=True)
def update_all():
    print("Updating all tools...")
    for tool, install_command in GO_TOOLS_MAP.items():
        subprocess.run(install_command, shell=True)
    
    for tool in PYTHON_PIP_TOOLS:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", tool])

    for tool_name, repo_url in {**PYTHON_GIT_TOOLS, **GIT_REPOS}.items():
        install_dir = ".huntools/python" if tool_name in PYTHON_GIT_TOOLS else ".huntools/git"
        repo_path = os.path.join(os.environ["HOME"], install_dir, tool_name)
        if os.path.exists(repo_path):
            subprocess.run(["git", "-C", repo_path, "pull"])

    package_manager = get_package_manager()
    if package_manager == "apt-get":
        subprocess.run(f"sudo {package_manager} update -y", shell=True)
        subprocess.run(f"sudo {package_manager} upgrade -y", shell=True)
    elif package_manager == "yum":
        subprocess.run(f"sudo {package_manager} update -y", shell=True)
    elif package_manager == "pacman":
        subprocess.run(f"sudo {package_manager} -Syu --noconfirm", shell=True)
    elif package_manager == "brew":
        subprocess.run("brew update && brew upgrade", shell=True)

def remove_single(tool_name):
    print(f"Removing single tool: {tool_name}")

    if tool_name not in ALL_TOOLS:
        print(f"\n{Colors.RED}Error: Tool '{tool_name}' not found.{Colors.NC}")
        print(f"{Colors.YELLOW}run 'huntools display --all' to see the list of available tools.{Colors.NC}\n")
        return

    tool = ALL_TOOLS[tool_name]
    tool_type = tool["type"]

    if tool_type == "go":
        gopath = os.path.join(os.environ.get("GOPATH", os.path.join(os.environ["HOME"], "go")), "bin", tool_name)
        if os.path.exists(gopath):
            os.remove(gopath)
            print(f"Removed {tool_name}")
        else:
            # If not in GOPATH, it might be in PATH, so try shutil.which
            tool_path = shutil.which(tool_name)
            if tool_path:
                os.remove(tool_path)
                print(f"Removed {tool_name} from {tool_path}")
            else:
                print(f"{tool_name} not found in GOPATH or PATH")

    elif tool_type == "pip":
        subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", tool_name])

    elif tool_type == "python_git":
        repo_path = os.path.join(os.environ["HOME"], ".huntools", "python", tool_name)
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)
            print(f"Removed {tool_name} repository.")
        else:
            print(f"Repository for {tool_name} not found.")

    elif tool_type == "git":
        repo_path = os.path.join(os.environ["HOME"], ".huntools", "git", tool_name)
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)
            print(f"Removed {tool_name} repository.")
        else:
            print(f"Repository for {tool_name} not found.")

    elif tool_type == "package":
        package_manager = get_package_manager()
        if package_manager in ["apt-get", "yum"]:
            subprocess.run(f"sudo {package_manager} remove -y {tool_name}", shell=True)
        elif package_manager == "pacman":
            subprocess.run(f"sudo {package_manager} -Rns --noconfirm {tool_name}", shell=True)
        elif package_manager == "brew":
            subprocess.run(f"brew uninstall {tool_name}", shell=True)
def remove_all():
    print("Removing all installed tools...")
    gopath_bin = os.path.join(os.environ.get("GOPATH", os.path.join(os.environ["HOME"], "go")), "bin")
    for tool in GO_TOOLS_MAP.keys():
        tool_path = os.path.join(gopath_bin, tool)
        if os.path.exists(tool_path):
            os.remove(tool_path)
    
    for tool in PYTHON_PIP_TOOLS:
        subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", tool])

    huntools_dir = os.path.join(os.environ["HOME"], ".huntools")
    if os.path.exists(huntools_dir):
        shutil.rmtree(huntools_dir)

    print("To remove system packages, please run the following command:")
    package_manager = get_package_manager()
    if package_manager in ["apt-get", "yum"]:
        print(f"sudo {package_manager} remove -y {' '.join(PACKAGE_TOOLS)}")
    elif package_manager == "pacman":
        print(f"sudo {package_manager} -Rns --noconfirm {' '.join(PACKAGE_TOOLS)}")
    elif package_manager == "brew":
        print(f"brew uninstall {' '.join(PACKAGE_TOOLS)}")

def clean_all():
    print("Purging all huntools data...")
    remove_all()
    config_dir = os.path.join(os.environ["HOME"], ".config", "huntools")
    if os.path.exists(config_dir):
        shutil.rmtree(config_dir)
    print("All huntools data has been removed.")

def self_update():
    print("Updating huntools...")
    try:
        subprocess.run(["git", "pull"], check=True)
        print("huntools updated successfully.")
    except subprocess.CalledProcessError:
        print("Update failed. Please make sure you are in the huntools git repository.")

def show_path():
    print("Displaying huntools paths:")
    huntools_dir = os.path.join(os.environ["HOME"], ".huntools")
    print(f"  - Installation directory: {huntools_dir}")
    print(f"  - Python tools directory: {os.path.join(huntools_dir, 'python')}")
    print(f"  - Git repos directory: {os.path.join(huntools_dir, 'git')}")
    print(f"  - Go binary path: {os.path.join(os.environ.get('GOPATH', os.path.join(os.environ['HOME'], 'go')), 'bin')}")
    print(f"  - Config file: {os.path.join(os.environ['HOME'], '.config', 'huntools', 'config.yml')}")

def show_changelog():
    changelog_path = "CHANGELOG.md"
    if os.path.exists(changelog_path):
        with open(changelog_path, "r") as f:
            print(f.read())
    else:
        print("CHANGELOG.md not found.")

def main():
    try:
        show_banner()

        parser = argparse.ArgumentParser(
            description="A streamlined tool for managing your bug hunting arsenal.",
            formatter_class=argparse.RawTextHelpFormatter,
            usage="huntools <command> [flags]"
        )

        subparsers = parser.add_subparsers(dest="command", title="Available commands", metavar=" ")

        # Install command
        install_parser = subparsers.add_parser("install", help="Install tools", add_help=False)
        install_parser.add_argument("-h", action="help", help="show this help message and exit")
        install_parser.add_argument("--help", action="help", help=argparse.SUPPRESS)
        install_parser.add_argument("-s", dest="install_single", help="Install a single, specified tool from the available list.", metavar="TOOL")
        install_parser.add_argument("--single", dest="install_single", help=argparse.SUPPRESS, metavar="TOOL")
        install_parser.add_argument("-a", dest="install_all", action="store_true", help="Install all available tools.")
        install_parser.add_argument("--all", dest="install_all", action="store_true", help=argparse.SUPPRESS)

        # Reinstall command
        reinstall_parser = subparsers.add_parser("reinstall", help="Reinstall a tool")
        reinstall_parser.add_argument("tool_name", help="The name of the tool to reinstall")

        # Update command
        update_parser = subparsers.add_parser("update", help="Update tools")
        update_parser.add_argument("-s", "--single", dest="update_single", help="Update a single, specified tool to its latest version.")
        update_parser.add_argument("-a", "--all", dest="update_all", action="store_true", help="Update all installed tools.")
        update_parser.add_argument("--self", dest="self_update", action="store_true", help="Update huntools to the latest version.")

        # Remove command
        remove_parser = subparsers.add_parser("remove", help="Remove tools")
        remove_parser.add_argument("-s", "--single", dest="remove_single", help="Remove a single, specified tool.")
        remove_parser.add_argument("-a", "--all", dest="remove_all", action="store_true", help="Remove all installed tools.")
        remove_parser.add_argument("--clean", dest="clean_all", action="store_true", help="Purge all huntools data, including configs and installed tools.")

        # Other commands
        display_parser = subparsers.add_parser("display", help="Display information")
        display_parser.add_argument("-a", "--all", dest="display_all", action="store_true", help="Show all tools available for installation.")
        
        check_parser = subparsers.add_parser("check", help="Check tool health")
        check_parser.add_argument("-hc", dest="checking_health", action="store_true", help="Perform a health check on all installed tools.")

        show_parser = subparsers.add_parser("show", help="Show information")
        show_parser.add_argument("--path", action="store_true", help="Display all relevant paths used by huntools.")
        show_parser.add_argument("--changelog", action="store_true", help="View the latest changes and updates to huntools.")

        config_parser = subparsers.add_parser("config", help="Configure huntools")
        config_parser.add_argument("-p", "--path", dest="config_path", help="Specify a custom path for the configuration file.\n(Default: ~/.config/huntools/config.yml)")
        config_parser.add_argument("-bp", "--binary-path", dest="binary_path", help="Set a custom directory for downloaded binaries.\n(Default: ~/.huntools/bin)")
        config_parser.add_argument("-ip", "--install-path", dest="install_path", help="Define the installation directory for all tools.\n(Default: ~/.huntools/)")

        args = parser.parse_args()

        if not args.command:
            parser.print_help(sys.stderr)
            sys.exit(1)

        if args.command == "install":
            if args.install_all:
                install_all()
            elif args.install_single:
                install_single(args.install_single)
        elif args.command == "reinstall":
            reinstall_single(args.tool_name)
        elif args.command == "display":
            if args.display_all:
                display_all()
        elif args.command == "check":
            if args.checking_health:
                checking_health()
        elif args.command == "update":
            if args.update_all:
                update_all()
            elif args.update_single:
                update_single(args.update_single)
            elif args.self_update:
                self_update()
        elif args.command == "remove":
            if args.remove_all:
                remove_all()
            elif args.remove_single:
                remove_single(args.remove_single)
            elif args.clean_all:
                clean_all()
        elif args.command == "show":
            if args.path:
                show_path()
            elif args.changelog:
                show_changelog()
        elif args.command == "config":
            if args.config_path:
                print(f"Setting config path to: {args.config_path}")
            if args.binary_path:
                print(f"Setting binary path to: {args.binary_path}")
            if args.install_path:
                print(f"Setting install path to: {args.install_path}")

    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}Installation aborted by user (Ctrl+C).{Colors.NC}")
        sys.exit(1)

if __name__ == "__main__":
    main()