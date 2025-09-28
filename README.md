<h1 align="center">🐞 Huntools</h1>
<br>
<p align="center">
    <a href="https://visitorbadge.io/status?path=https%3A%2F%2Fgithub.com%2Fl0n3m4n%2FSearchToolkit">
        <img src="https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2Fl0n3m4n%2Fbughunting-automation&label=Visitors&countColor=%2337d67a" />
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
    <a href="mailto:l0n3m4n@proton.me">
      <img src="https://img.shields.io/badge/ProtonMail-6001D2?style=for-the-badge&logo=protonmail&logoColor=white" alt="ProtonMail">
    </a>
</p>
<br/>

```bash
~>  sudo python3 huntools.py
 __  __     __  __     __   __     ______   ______   ______     ______     __         ______    
/\ \_\ \   /\ \/\ \   /\ "-.\ \   /\__  _\ /\__  _\ /\  __ \   /\  __ \   /\ \       /\  ___\   
\ \  __ \  \ \ \_\ \  \ \ \-.  \  \/_/\ \/ \/_/\ \/ \ \ \/\ \  \ \ \/\ \  \ \ \____  \ \___  \  
 \ \_\ \_\  \ \_____\  \ \_\\"\_\    \ \_\    \ \_\  \ \_____\  \ \_____\  \ \_____\  \/\_____\ 
  \/_/\/_/   \/_____/   \/_/ \/_/     \/_/     \/_/   \/_____/   \/_____/   \/_____/   \/_____/ 
                                                                                                                      
            Author: l0n3m4n | Version: 1.0.0 | Bughunting Automation Installer 

A lightweight Python automation script to install essential tools for bug bounty and penetration testing via APT or GitHub clone fallback — with smart checks and status reporting.

[*] Starting tool installation process...

[6%] Checking seclists (1/15)
[+] seclists is already installed.

[13%] Checking jq (2/15)
[+] jq is already installed.

[100%] Checking shodan (15/15)
[+] shodan is already installed.


Summary:
  Installed via APT or already present: 15
  Installed manually from GitHub: 0
  Failed to install: 0

[✓] All tools checked and processed.

Summary: 15 tool(s) installed via APT or already present.
         0 tool(s) cloned from GitHub.
~>                                        
```
---

## 🚀 Features

- ✅ One-line install for multiple tools
- 📦 Installs via APT where available
- 🌐 Falls back to GitHub repo clone if APT fails
- 🔍 Skips if the tool already exists or is cloned under `/opt`
- 🧠 Detects and counts APT-installed and manually-installed tools
- 🔐 Supports GitHub token to avoid API rate limits

---

## 🧰 Tools Included

- `seclists`
- `jq`
- `ffuf`
- `gobuster`
- `feroxbuster`
- `katana`
- `flameshot`
- `lsd`
- `subfinder`
- `assetfinder`
- `aquatone`
- `gau`
- `waybackurls`
- `OneForAll`

---

## 📦 Installation

1. **Clone the repository:**

```bash
git clone https://github.com/l0n3m4n/huntools.git
cd huntools
sudo python3 huntools.py 
```
## 🔐 GitHub Token (Optional)

Set a GitHub token to avoid API rate limits during repo searches:
```
export GITHUB_TOKEN=ghp_yourtokenhere
```
You can create one at: https://github.com/settings/tokens

## 📋 TODO 
- [ ] Dockerfile   


## 🙌 Contributing
Pull requests are welcome! If you'd like to contribute tools or improvements, feel free to fork and submit a PR.

📣 Disclaimer

This tool is provided as-is for educational and lawful bug bounty purposes. Use it responsibly and only on systems you own or have explicit permission to test.
