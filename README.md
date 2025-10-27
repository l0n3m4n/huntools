<h1 align="center"><img src="logo.gif" alt="Huntools Logo" width="25"/> Huntools</h1>

<br>
 
<p align="center">
    <a href="https://visitorbadge.io/status?path=https%3A%2F%2Fgithub.com%2Fl0n3m4n%2Fhuntools">
        <img src="https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2Fl0n3m4n%2Fhuntools&label=Visitors&countColor=%2337d67a" />
    </a>
    <a href="https://www.facebook.com/UEVOLVJU">
        <img src="https://img.shields.io/badge/Facebook-%231877F2.svg?style=for-the-badge&logo=Facebook&logoColor=white" alt="Facebook">
    </a>
      <a href="https://www.twitter.com/UEVOLVJU">
        <img src="https://img.shields.io/badge/Twitter-%23000000.svg?style=for-the-badge&logo=X&logoColor=white" alt="X">
    </a>
    <a href="https://medium.com/@l0n3m4n">
        <img src="https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white" alt="Medium">
    </a>
    <a href="https://www.buymeacoffee.com/l0n3m4n">
        <img src="https://img.shields.io/badge/Buy%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me a Coffee">
    </a>  
    <a href="mailto:l0n3m4n@proton.me">
      <img src="https://img.shields.io/badge/ProtonMail-6001D2?style=for-the-badge&logo=protonmail&logoColor=white" alt="ProtonMail">
    </a>
</p>
<br/>



Huntools is a Python based command line utility crafted for penetration testers and bug bounty hunters. It    
provides a robust and streamlined solution for managing your entire arsenal of reconnaissance, vulnerability analysis, exploitation tools etc. With this tool you gain    
unparalleled control over tool installation, ensuring your toolkit is always optimized, consistent, portable, and ready  
for critical operations.


## 🚀 Features

- ✅ **Robust Installation:** Automated installation of tools via system package managers, pip, or Git cloning.
- 🛡️ **Checksum Verification:** Ensures integrity of downloaded Go tools to prevent corruption.
- 🩹 **Installation Handling:** Detects and repairs partially cloned Git repositories.
- 🔄 **Reinstall Command:** Easily fix corrupted tools by performing a fresh reinstallation.
- 📊 **Tool Count:** The banner now dynamically displays the total number of available tools.
- 🛠️ **Tool Management:** All tools are managed from a single, extensible data structure, making the script maintainable.
- 🔍 **Smart Checks:** Skips installation if a tool is already present in your system's PATH.
- 🌐 **Cross-Platform:** Designed to work across various operating systems, Linux distrus Debian, Ubuntu, Fedora, and Arch
- 🐳 **Docker Support:** Generate a `Dockerfile` to create a consistent and portable Huntools environment.

---

## 🛠️ Available Tools



Here is a list of all the tools that Huntools can manage, categorized by their function.



### Reconnaissance: Subdomain Enumeration



|   |   |   |   |

|---|---|---|---|

| `subfinder` | `assetfinder` | `Amass` | `ShuffleDNS` |

| `github-subdomains` | `gitlab-subdomains` | `puredns` | `OneForAll` |

| `sns` |   |   |   |



### Reconnaissance: Content Discovery & Crawling



|   |   |   |

|---|---|---|

| `feroxbuster` | `katana` | `GoSpider` |



### Reconnaissance: OSINT & Dorking



|   |   |   |   |

|---|---|---|---|

| `metabigor` | `analyticsrelationships` | `gitdorks_go` | `mantra` |

| `cent` | `dorks_hunter` | `regulator` | `LeakSearch` |

| `metagoofil` | `censys` | `shodan` | `enumerepo` |



### Reconnaissance: Web & API



|   |   |   |   |

|---|---|---|---|

| `gau` | `waybackurls` | `httpx` | `github-endpoints` |

| `subjs` | `roboxtractor` | `shortscan` | `ppmap` |

| `sourcemapper` | `jsluice` | `urlfinder` | `csprecon` |

| `VhostFinder` | `LinkFinder` | `fav-up` | `JSA` |

| `SwaggerSpy` | `wafw00f` | `xnLinkFinder` |   |



### Reconnaissance: Cloud



|   |   |   |   |

|---|---|---|---|

| `s3scanner` | `cloud_enum` | `CloudHunter` | `msftrecon` |

| `porch-pirate` |   |   |   |



### Reconnaissance: Network, Port Scanning & TLS



|   |   |   |   |

|---|---|---|---|

| `Naabu` | `ct-exposer` | `tlsx` | `smap` |

| `nmap` | `crt` |   |   |



### Fuzzing



|   |   |   |

|---|---|---|

| `ffuf` | `crlfuzz` | `nomore403` |



### Vulnerability Scanning: Web (XSS, CORS, Cache, etc.)



|   |   |   |   |

|---|---|---|---|

| `Gxss` | `dalfox` | `Corsy` | `Oralyzer` |

| `smuggler` | `Spoofy` | `Web-Cache-Vulnerability-Scanner` |   |



### Vulnerability Scanning: Subdomain Takeover



|   |

|---|

| `dnstake` |



### Vulnerability Scanning: Secrets Scanning



|   |   |

|---|---|

| `gitleaks` | `trufflehog` |



### Vulnerability Scanning: General & Other



|   |   |   |   |

|---|---|---|---|

| `Nuclei` | `gf` | `misconfig-mapper` | `CMSeeK` |



### Exploitation



|   |

|---|

| `commix` |



### DNS Tools



|   |   |   |

|---|---|---|

| `DNSx` | `massdns` | `hakip2host` |



### Wordlists & Payloads



|   |   |   |   |

|---|---|---|---|

| `gotator` | `cewl` | `pydictor` | `seclists` |

| `sus_params` | `Gf-Patterns` |   |   |



### Utilities



|   |   |   |   |

|---|---|---|---|

| `qsreplace` | `anew` | `notify` | `unfurl` |

| `mapcidr` | `cdncheck` | `dsieve` | `inscope` |

| `nmapurls` | `jq` | `flameshot` | `lsd` |

| `Scopify` | `urless` | `p1radup` |   |



### Brute Force



|   |

|---|

| `brutespray` |



---





```bash
~>  sudo python3 huntools.py

  ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓ ▒█████   ▒█████   ██▓      ██████ 
▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    ▒██    ▒ 
▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    ░ ▓██▄   
░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░      ▒   ██▒
░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒▒██████▒▒
 ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░▒ ▒▓▒ ▒ ░
 ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░░ ░▒  ░ ░
 ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   ░  ░  ░  
 ░  ░  ░   ░              ░              ░ ░      ░ ░      ░  ░      ░  
                                                                        
            Author: l0n3m4n | Version: 3.3.0 | 111 Hunter Tools

usage: huntools <command> [flags]

A streamlined tool for managing your hunting arsenal.

options:
  -h, --help   show this help message and exit

Available commands:
   
    install    Install tools
    reinstall  Reinstall a tool
    update     Update tools
    remove     Remove tools
    display    Display all tools
    check      Check tool health
    show       Show information
    config     Configure huntools
    docker     Manage Docker image

```

---

## 💡 Usage and Installation: 
 

### 🚀 Initial Setup & Installation

1.  **Clone the Huntools Repository:**
    
    ```bash
    git clone https://github.com/l0n3m4n/huntools.git
    cd huntools
    ```

2.  **Install All Tools (Recommended for First-Time Setup):**

    This command will install all the tools Huntools manages, along with necessary system dependencies and Go (if not already present).
    ```bash
    sudo python3 huntools.py install -a
    ```
    *   *Friendly Tip:* This is the easiest way to get your full arsenal ready!

3.  **Install a Single Tool:**
  
    If you only need a specific tool, you can install it individually.
    ```bash
    sudo python3 huntools.py install -s <tool_name>
    ```
    *   *Example:* `sudo python3 huntools.py install -s subfinder`

4.  **System-wide Installation (Optional):**

    To make `huntools` accessible from anywhere, you can install it to `/usr/local/bin`.
    ```bash
    sudo python3 huntools.py install -is
    ```
    After this, you can run the tool simply by typing `huntools`.

### ⚙️ Customizing Huntools (Configuration)

Huntools allows you to customize paths for its configuration, binaries, and installed tools.

*   **Important Note:** 

Configuration changes are applied *before* running other commands that rely on them. You cannot combine configuration options with other commands (like `install`) in a single line.

1.  **Specify a Custom Configuration File Path:**

    Use this if you want Huntools to use a configuration file from a non-default location.
    ```bash
    python3 huntools.py config -cp ~/.my_custom_huntools_config/config.yml
    ```
    *   *Default:* `~/.config/huntools/config.yml`

2.  **Set a Custom Directory for Downloaded Binaries:**

    Define where Huntools should store Go binaries and other executables.
    ```bash
    python3 huntools.py config -bp /opt/huntools_binaries
    ```
    *   *Default:* `~/.huntools/bin`

3.  **Define the Installation Directory for All Tools:**

    This sets the base directory where Huntools will clone Git repositories and manage other tool-specific files.
    ```bash
    python3 huntools.py config -ip /opt/huntools_tools
    ```
    *   *Default:* `~/.huntools/`

### 🔄 Managing & Maintaining Your Tools

Once installed, Huntools helps you keep your arsenal sharp.

1.  **Update All Tools:**
    Keep your entire toolkit up-to-date with the latest versions.
    ```bash
    huntools update -ua
    ```

2.  **Update a Single Tool:**
    Update a specific tool if you prefer.
    ```bash
    huntools update -s <tool_name>
    ```
    *   *Example:* `huntools update -s nuclei`

3.  **Update Huntools Itself:**

    Ensure Huntools is running its latest version.
    ```bash
    huntools update -su
    ```

4.  **Reinstall a Tool:**
    If a tool becomes corrupted or you need a fresh start, reinstall it.
    ```bash
    huntools reinstall <tool_name>
    ```
    *   *Example:* `huntools reinstall ffuf`

5.  **Check Tool Health:**

    See which tools are installed and their detected locations.
    ```bash
    huntools check -hc
    ```

### 🔍 Viewing Information

Huntools provides commands to quickly access important information.

1.  **Display All Available Tools:**

    Get a full list of all the tools Huntools can manage.
    ```bash
    huntools display -a
    ```

2.  **Show Huntools Paths:**

    See where Huntools stores its files and configurations.
    ```bash
    huntools show -pl
    ```

3.  **View Changelog:**
    Catch up on what's new and improved in Huntools.
    ```bash
    huntools show -cl
    ```

### 🗑️ Step 5: Removing Tools & Data

When it's time to clean up, Huntools has you covered.

1.  **Remove a Single Tool:**

    Remove a specific tool from your system. You'll be prompted for confirmation, showing its location and any `sudo` requirements.
    ```bash
    huntools remove -rs <tool_name>
    ```
    *   *Example:* `huntools remove -rs dalfox`

2.  **Remove All Tools:**

    This will remove all installed tools. You will receive a confirmation prompt showing the number of tools to be removed.
    ```bash
    huntools remove -ra
    ```

3.  **Purge All Huntools Data:**

    The ultimate cleanup! This removes all tools, configurations, and Huntools-related data. A confirmation prompt will appear.
    ```bash
    huntools remove -ca
    ```
    *   *Note:* Use with extreme caution, as this is irreversible!

### 🐳 Docker Integration

For consistent, isolated, and portable tool management, Huntools supports Docker.

1.  **Generate the Dockerfile:**

    Output a `Dockerfile` tailored for Huntools. By default, it creates a file named `Dockerfile` in your current directory.
    ```bash
    python3 huntools.py docker -g
    ```
    To specify a different filename, use the `-s` option:
    ```bash
    python3 huntools.py docker -g -s my_custom_dockerfile
    ```

2.  **Build the Docker Image:**
    Navigate to the directory containing the generated `Dockerfile` and your `huntools.py` script, then build the Docker image.
    ```bash
    docker build -t huntools-env .
    ```
    *   *Friendly Tip:* This creates a Docker image named `huntools-env` with all tools pre-installed.

3.  **Run the Docker Container:**
    *   **Interactive Shell:** Get a shell inside the container with all tools available.
        ```bash
        docker run -it huntools-env bash
        ```
    *   **Execute a Huntools Command Directly:**
        ```bash
        docker run huntools-env huntools <command> [options]
        # Example: docker run huntools-env huntools display -a
        ```

---

## 🔐 GitHub Token (Optional)

Set a GitHub token to avoid API rate limits during repo searches:
```bash
export GITHUB_TOKEN=ghp_yourtokenhere
```
You can create one at: https://github.com/settings/tokens

---

## 🙌 Contributing
Pull requests are welcome! If you'd like to contribute tools or improvements, feel free to fork and submit a PR.

📣 Disclaimer

This tool is provided as-is for educational and lawful bug bounty purposes. Use it responsibly and only on systems you own or have explicit permission to test.

Stay sharp, stay secure.
