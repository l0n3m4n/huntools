#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import shutil
import platform
import configparser

# Tool lists
# Merged from huntools.sh and install.sh
PACKAGE_TOOLS = ["seclists", "jq", "flameshot", "lsd", "cewl", "nmap", "massdns", "testssl.sh"]

PYTHON_GIT_TOOLS = {
    "LinkFinder": "https://github.com/GerbenJavado/LinkFinder.git",
    "OneForAll": "https://github.com/shmilylty/OneForAll.git",
    "Sublist3r": "https://github.com/aboul3la/Sublist3r.git",
    "SubDomainizer": "https://github.com/nsonaniya2010/SubDomainizer.git",
    "cloud_enum": "https://github.com/initstring/cloud_enum.git",
    "dorks_hunter": "https://github.com/six2dez/dorks_hunter.git",
    "Corsy": "https://github.com/s0md3v/Corsy.git",
    "CMSeeK": "https://github.com/Tuhinshubhra/CMSeeK.git",
    "fav-up": "https://github.com/pielco11/fav-up.git",
    "Oralyzer": "https://github.com/r0075h3ll/Oralyzer.git",
    "JSA": "https://github.com/w9w/JSA.git",
    "CloudHunter": "https://github.com/belane/CloudHunter.git",
    "ultimate-nmap-parser": "https://github.com/shifty0g/ultimate-nmap-parser.git",
    "pydictor": "https://github.com/LandGrey/pydictor.git",
    "smuggler": "https://github.com/defparam/smuggler.git",
    "regulator": "https://github.com/cramppet/regulator.git",
    "nomore403": "https://github.com/devploit/nomore403.git",
    "SwaggerSpy": "https://github.com/UndeadSec/SwaggerSpy.git",
    "LeakSearch": "https://github.com/JoelGMSec/LeakSearch.git",
    "ffufPostprocessing": "https://github.com/Damian89/ffufPostprocessing.git",
    "Spoofy": "https://github.com/MattKeeley/Spoofy.git",
    "msftrecon": "https://github.com/Arcanum-Sec/msftrecon.git",
    "Scopify": "https://github.com/Arcanum-Sec/Scopify.git",
    "metagoofil": "https://github.com/opsdisk/metagoofil.git",
    "EmailHarvester": "https://github.com/maldevel/EmailHarvester.git",
    "reconftw_ai": "https://github.com/six2dez/reconftw_ai.git"
}

PYTHON_PIP_TOOLS = ["censys", "shodan", "dnsvalidator", "interlace", "wafw00f", "commix", "urless", "ghauri", "xnLinkFinder", "xnldorker", "porch-pirate", "p1radup", "subwiz"]

GO_TOOLS_MAP = {
    "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest",
    "feroxbuster": "go install -v github.com/epi052/feroxbuster@latest",
    "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install -v github.com/tomnomnom/assetfinder@latest",
    "aquatone": "go install -v github.com/michenriksen/aquatone@latest",
    "gau": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "go install -v github.com/tomnomnom/waybackurls@latest",
    "Amass": "go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "GoSpider": "go install -v github.com/jaeles-project/gospider@latest",
    "ShuffleDNS": "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
    "Nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "DNSx": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "Naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "ct-exposer": "go get -u github.com/crt.sh/ct-exposer",
    "metabigor": "go install -v github.com/j3ssie/metabigor@latest",
    "gf": "go install -v github.com/tomnomnom/gf@latest",
    "brutespray": "go install -v github.com/x90skysn3k/brutespray@latest",
    "qsreplace": "go install -v github.com/tomnomnom/qsreplace@latest",
    "github-subdomains": "go install -v github.com/gwen001/github-subdomains@latest",
    "gitlab-subdomains": "go install -v github.com/gwen001/gitlab-subdomains@latest",
    "anew": "go install -v github.com/tomnomnom/anew@latest",
    "notify": "go install -v github.com/projectdiscovery/notify/cmd/notify@latest",
    "unfurl": "go install -v github.com/tomnomnom/unfurl@v0.3.0",
    "github-endpoints": "go install -v github.com/gwen001/github-endpoints@latest",
    "subjs": "go install -v github.com/lc/subjs@latest",
    "Gxss": "go install -v github.com/KathanP19/Gxss@latest",
    "crlfuzz": "go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
    "dalfox": "go install -v github.com/hahwul/dalfox/v2@latest",
    "puredns": "go install -v github.com/d3mondev/puredns/v2@latest",
    "interactsh-client": "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "analyticsrelationships": "go install -v github.com/Josue87/analyticsrelationships@latest",
    "gotator": "go install -v github.com/Josue87/gotator@latest",
    "roboxtractor": "go install -v github.com/Josue87/roboxtractor@latest",
    "mapcidr": "go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
    "cdncheck": "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
    "dnstake": "go install -v github.com/pwnesia/dnstake/cmd/dnstake@latest",
    "tlsx": "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    "gitdorks_go": "go install -v github.com/damit5/gitdorks_go@latest",
    "smap": "go install -v github.com/s0md3v/smap/cmd/smap@latest",
    "dsieve": "go install -v github.com/trickest/dsieve@master",
    "inscope": "go install -v github.com/tomnomnom/hacks/inscope@latest",
    "enumerepo": "go install -v github.com/trickest/enumerepo@latest",
    "Web-Cache-Vulnerability-Scanner": "go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest",
    "hakip2host": "go install -v github.com/hakluke/hakip2host@latest",
    "mantra": "go install -v github.com/Brosck/mantra@latest",
    "crt": "go install -v github.com/cemulus/crt@latest",
    "s3scanner": "go install -v github.com/sa7mon/s3scanner@latest",
    "nmapurls": "go install -v github.com/sdcampbell/nmapurls@latest",
    "shortscan": "go install -v github.com/bitquark/shortscan/cmd/shortscan@latest",
    "sns": "go install github.com/sw33tLie/sns@latest",
    "ppmap": "go install -v github.com/kleiton0x00/ppmap@latest",
    "sourcemapper": "go install -v github.com/denandz/sourcemapper@latest",
    "jsluice": "go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest",
    "urlfinder": "go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest",
    "cent": "go install -v github.com/xm1k3/cent@latest",
    "csprecon": "go install github.com/edoardottt/csprecon/cmd/csprecon@latest",
    "VhostFinder": "go install -v github.com/wdahlenburg/VhostFinder@latest",
    "misconfig-mapper": "go install github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper@latest",
    "gitleaks": "go install -v github.com/gitleaks/gitleaks/v8@latest",
    "trufflehog": "go install -v github.com/trufflesecurity/trufflehog/v3@latest"
}

GIT_REPOS = {
    "Gf-Patterns": "https://github.com/1ndianl33t/Gf-Patterns.git",
    "sus_params": "https://github.com/g0ldencybersec/sus_params.git",
    "testssl.sh": "https://github.com/drwetter/testssl.sh.git"
}

# Colors
class Colors:
    BLUE = '''\033[1;34m'''
    NC = '''\033[0m'''
    GREEN = '''\033[0;32m'''
    RED = '''\033[0;31m'''

def show_banner():
    banner = """
    
  ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓ ▒█████   ▒█████   ██▓      ██████ 
▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    ▒██    ▒ 
▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    ░ ▓██▄   
░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░      ▒   ██▒
░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒▒██████▒▒
 ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░▒ ▒▓▒ ▒ ░
 ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░░ ░▒  ░ ░
 ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   ░  ░  ░  
 ░  ░  ░   ░              ░              ░ ░      ░ ░      ░  ░      ░  
                                                                        
        Author: l0n3m4n | Version: 2.0.0 | Bughunting Installer 
"""
    print(f"{Colors.BLUE}{banner}{Colors.NC}")

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
    print("Installing system dependencies...")
    package_manager = get_package_manager()
    if not package_manager:
        print("Unsupported OS. Please install dependencies manually.")
        return

    deps = {
        "apt-get": "python3 python3-pip python3-venv git curl wget ruby nmap build-essential gcc cmake libpcap-dev dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev",
        "yum": "python3 python3-pip python3-devel git curl wget ruby nmap gcc gcc-c++ make cmake pcap-devel dnsutils openssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel",
        "pacman": "python python-pip python-virtualenv git curl wget ruby nmap base-devel gcc cmake libpcap dnsutils openssl libffi libxml2 libxslt zlib",
        "brew": "python git curl wget ruby nmap cmake"
    }

    if package_manager == "apt-get":
        subprocess.run(f"sudo {package_manager} update -y", shell=True)
        subprocess.run(f"sudo {package_manager} install -y {deps[package_manager]}", shell=True)
    elif package_manager == "yum":
        subprocess.run(f"sudo {package_manager} install -y {deps[package_manager]}", shell=True)
    elif package_manager == "pacman":
        subprocess.run(f"sudo {package_manager} -Syu --noconfirm {deps[package_manager]}", shell=True)
    elif package_manager == "brew":
        subprocess.run(f"{package_manager} update", shell=True)
        subprocess.run(f"{package_manager} install {deps[package_manager]}", shell=True)

def install_go():
    if shutil.which("go"):
        print("Go is already installed.")
        return

    print("Installing Go...")
    try:
        version_url = "https://go.dev/VERSION?m=text"
        version_res = subprocess.run(["curl", "-s", version_url], capture_output=True, text=True)
        version = version_res.stdout.strip() if version_res.returncode == 0 else "go1.20.7"
    except Exception:
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
        print(f"Unsupported architecture: {arch}. Please install Go manually.")
        sys.exit(1)

    go_url = f"https://dl.google.com/go/{version}.{os_name}-{arch}.tar.gz"
    go_tar_path = "/tmp/go.tar.gz"

    subprocess.run(["wget", go_url, "-O", go_tar_path])
    subprocess.run(["sudo", "rm", "-rf", "/usr/local/go"])
    subprocess.run(["sudo", "tar", "-C", "/usr/local", "-xzf", go_tar_path])
    os.remove(go_tar_path)

    goroot = "/usr/local/go"
    gopath = os.path.join(os.environ["HOME"], "go")
    
    with open(os.path.join(os.environ["HOME"], ".bashrc"), "a") as f:
        f.write("\n# Go environment variables\n")
        f.write(f"export GOROOT={goroot}\n")
        f.write(f"export GOPATH={gopath}\n")
        f.write(f"export PATH=$GOPATH/bin:$GOROOT/bin:$PATH\n")

    print("Go has been installed. Please restart your shell or run 'source ~/.bashrc'")

def install_go_tools():
    print("Installing Go tools...")
    for tool, install_command in GO_TOOLS_MAP.items():
        print(f"Installing {tool}...")
        subprocess.run(install_command, shell=True)

def install_packages():
    print("Installing packages...")
    package_manager = get_package_manager()
    if not package_manager:
        print(f"Unsupported OS for package installation. Please install manually: {' '.join(PACKAGE_TOOLS)}")
        return

    if package_manager == "apt-get":
        subprocess.run(f"sudo {package_manager} install -y {' '.join(PACKAGE_TOOLS)}", shell=True)
    elif package_manager == "yum":
        subprocess.run(f"sudo {package_manager} install -y {' '.join(PACKAGE_TOOLS)}", shell=True)
    elif package_manager == "pacman":
        subprocess.run(f"sudo {package_manager} -S --noconfirm {' '.join(PACKAGE_TOOLS)}", shell=True)
    elif package_manager == "brew":
        subprocess.run(f"{package_manager} install {' '.join(PACKAGE_TOOLS)}", shell=True)

def install_python_tools():
    print("Installing Python tools...")
    install_dir = os.path.join(os.environ["HOME"], ".huntools", "python")
    os.makedirs(install_dir, exist_ok=True)

    for tool_name, repo_url in PYTHON_GIT_TOOLS.items():
        print(f"Installing {tool_name} from git...")
        repo_path = os.path.join(install_dir, tool_name)
        subprocess.run(["git", "clone", repo_url, repo_path])
        
        requirements_path = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(requirements_path):
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", requirements_path])

    for tool in PYTHON_PIP_TOOLS:
        print(f"Installing {tool} from pip...")
        subprocess.run([sys.executable, "-m", "pip", "install", tool])

def install_git_repos():
    print("Cloning other git repositories...")
    install_dir = os.path.join(os.environ["HOME"], ".huntools", "git")
    os.makedirs(install_dir, exist_ok=True)

    for repo_name, repo_url in GIT_REPOS.items():
        print(f"Cloning {repo_name}...")
        repo_path = os.path.join(install_dir, repo_name)
        subprocess.run(["git", "clone", repo_url, repo_path])

def install_all():
    install_dependencies()
    install_go()
    install_go_tools()
    install_packages()
    install_python_tools()
    install_git_repos()
    print("All tools installed.")

def install_single(tool_name):
    print(f"Attempting to install single tool: {tool_name}")

    if tool_name in GO_TOOLS_MAP:
        print(f"Installing Go tool: {tool_name}")
        subprocess.run(GO_TOOLS_MAP[tool_name], shell=True)
        return

    if tool_name in PACKAGE_TOOLS:
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
        return

    if tool_name in PYTHON_GIT_TOOLS:
        print(f"Installing Python tool from git: {tool_name}")
        install_dir = os.path.join(os.environ["HOME"], ".huntools", "python")
        os.makedirs(install_dir, exist_ok=True)
        repo_url = PYTHON_GIT_TOOLS[tool_name]
        repo_path = os.path.join(install_dir, tool_name)
        subprocess.run(["git", "clone", repo_url, repo_path])
        
        requirements_path = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(requirements_path):
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", requirements_path])
        return

    if tool_name in PYTHON_PIP_TOOLS:
        print(f"Installing Python tool from pip: {tool_name}")
        subprocess.run([sys.executable, "-m", "pip", "install", tool_name])
        return
        
    if tool_name in GIT_REPOS:
        print(f"Cloning git repository: {tool_name}")
        install_dir = os.path.join(os.environ["HOME"], ".huntools", "git")
        os.makedirs(install_dir, exist_ok=True)
        repo_url = GIT_REPOS[tool_name]
        repo_path = os.path.join(install_dir, tool_name)
        subprocess.run(["git", "clone", repo_url, repo_path])
        return

    print(f"Tool '{tool_name}' not found in any of the predefined tool lists.")

def display_all():
    print("Available tools:")
    all_tools = sorted(
        list(GO_TOOLS_MAP.keys()) + 
        list(PYTHON_GIT_TOOLS.keys()) + 
        PYTHON_PIP_TOOLS + 
        PACKAGE_TOOLS + 
        list(GIT_REPOS.keys())
    )
    for tool in all_tools:
        print(f"  - {tool}")

def checking_health():
    print("Performing health check on all tools...")
    all_tools = sorted(
        list(GO_TOOLS_MAP.keys()) + 
        list(PYTHON_GIT_TOOLS.keys()) + 
        PYTHON_PIP_TOOLS + 
        PACKAGE_TOOLS + 
        list(GIT_REPOS.keys())
    )
    for tool in all_tools:
        if shutil.which(tool):
            print(f"  - {tool}: {Colors.GREEN}Installed{Colors.NC}")
            continue

        if tool in PYTHON_GIT_TOOLS:
            repo_path = os.path.join(os.environ["HOME"], ".huntools", "python", tool)
            if os.path.exists(repo_path):
                print(f"  - {tool}: {Colors.GREEN}Installed (Python Git Repo){Colors.NC}")
                continue
        
        if tool in GIT_REPOS:
            repo_path = os.path.join(os.environ["HOME"], ".huntools", "git", tool)
            if os.path.exists(repo_path):
                print(f"  - {tool}: {Colors.GREEN}Installed (Git Repo){Colors.NC}")
                continue

        print(f"  - {tool}: {Colors.RED}Not Found{Colors.NC}")

def update_single(tool_name):
    print(f"Updating single tool: {tool_name}")
    if tool_name in GO_TOOLS_MAP:
        subprocess.run(GO_TOOLS_MAP[tool_name], shell=True)
        return

    if tool_name in PYTHON_PIP_TOOLS:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", tool_name])
        return

    if tool_name in PYTHON_GIT_TOOLS or tool_name in GIT_REPOS:
        install_dir = ".huntools/python" if tool_name in PYTHON_GIT_TOOLS else ".huntools/git"
        repo_path = os.path.join(os.environ["HOME"], install_dir, tool_name)
        if os.path.exists(repo_path):
            subprocess.run(["git", "-C", repo_path, "pull"])
        else:
            print(f"Tool {tool_name} not found in {repo_path}. Cannot update.")
        return
    
    if tool_name in PACKAGE_TOOLS:
        package_manager = get_package_manager()
        if package_manager == "apt-get":
            subprocess.run(f"sudo {package_manager} install --only-upgrade -y {tool_name}", shell=True)
        elif package_manager == "yum":
            subprocess.run(f"sudo {package_manager} update -y {tool_name}", shell=True)
        elif package_manager == "pacman":
            print("For Arch Linux, please run 'sudo pacman -Syu' to update all packages.")
        elif package_manager == "brew":
            subprocess.run(f"brew upgrade {tool_name}", shell=True)
        return

    print(f"Tool '{tool_name}' not found or update not supported for this type of tool.")

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
    if tool_name in GO_TOOLS_MAP:
        gopath = os.path.join(os.environ.get("GOPATH", os.path.join(os.environ["HOME"], "go")), "bin", tool_name)
        if os.path.exists(gopath):
            os.remove(gopath)
            print(f"Removed {tool_name}")
        else:
            print(f"{tool_name} not found in GOPATH")
        return

    if tool_name in PYTHON_PIP_TOOLS:
        subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", tool_name])
        return

    if tool_name in PYTHON_GIT_TOOLS or tool_name in GIT_REPOS:
        install_dir = ".huntools/python" if tool_name in PYTHON_GIT_TOOLS else ".huntools/git"
        repo_path = os.path.join(os.environ["HOME"], install_dir, tool_name)
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)
            print(f"Removed {tool_name} repository.")
        else:
            print(f"Repository for {tool_name} not found.")
        return

    if tool_name in PACKAGE_TOOLS:
        package_manager = get_package_manager()
        if package_manager in ["apt-get", "yum"]:
            subprocess.run(f"sudo {package_manager} remove -y {tool_name}", shell=True)
        elif package_manager == "pacman":
            subprocess.run(f"sudo {package_manager} -Rns --noconfirm {tool_name}", shell=True)
        elif package_manager == "brew":
            subprocess.run(f"brew uninstall {tool_name}", shell=True)
        return

    print(f"Tool '{tool_name}' not found or remove not supported for this type of tool.")

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
    show_banner()

    parser = argparse.ArgumentParser(
        description="A streamlined tool for managing your bug hunting arsenal.",
        formatter_class=argparse.RawTextHelpFormatter,
        usage="huntools <command> [flags]"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Install command
    install_parser = subparsers.add_parser("install", help="Install tools")
    install_parser.add_argument("-s", "--single", dest="install_single", help="Install a single, specified tool from the available list.")
    install_parser.add_argument("-a", "--all", dest="install_all", action="store_true", help="Install all available tools.")

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
    check_parser.add_argument("--health", dest="checking_health", action="store_true", help="Perform a health check on all installed tools.")

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

if __name__ == "__main__":
    main()