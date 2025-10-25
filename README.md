<h1 align="center">🐞 Huntools</h1>
<br>
<p align="center">
    <a href="https://visitorbadge.io/status?path=https%3A%2F%2Fgithub.com%2Fl0n3m4n%2FSearchToolkit">
        <img src="https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2Fl0n3m4m%2Fbughunting-automation&label=Visitors&countColor=%2337d67a" />
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
/\ \_\ \   /\ \/\ \   /\ "-.\ \   /\__  _\ /\__  _\ /\  __ \   /\  __ \   /\ \       /\  __ _  \
\ \  __ \  \ \ \_\ \  \ \ \-.  \  \/_/\ \/ \/_/\ \/ \ \ \/\ \  \ \ \/\ \  \ \ \____  \ \___  \
 \ \_\ \_\  \ \_____\  \ \_\\"\_\    \ \_\    \ \_\  \ \_____\  \ \_____\  \ \_____\  \/\_____\
  \/_/\/_/   \/_____/   \/_/ \/_/     \/_/     \/_/   \/_____/   \/_____/   \/_____/   \/_____/
                                                                                                                      
            Author: l0n3m4n | Version: 2.0.0 | XX Hunter's Arsenal 

A robust Python script to manage your bug hunting arsenal, featuring automated installation, health checks, and updates for a comprehensive set of tools.

## 🚀 Features

- ✅ **Robust Installation:** Automated installation of tools via system package managers, pip, or Git cloning.
- 🛡️ **Checksum Verification:** Ensures integrity of downloaded Go tools to prevent corruption.
- 🩹 **Incomplete Installation Handling:** Detects and repairs partially cloned Git repositories.
- 🔄 **Reinstall Command:** Easily fix corrupted tools by performing a fresh reinstallation.
-  gracefully **Ctrl+C Handling:** Allows for clean and graceful abortion of ongoing processes.
- 📊 **Dynamic Tool Count:** The banner now dynamically displays the total number of available tools.
- 🔍 **Smart Checks:** Skips installation if a tool is already present in your system's PATH.
- 🛠️ **Unified Tool Management:** All tools are managed from a single, extensible data structure, making the script highly maintainable and scalable.

---

## 📦 Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/l0n3m4n/huntools.git
    cd huntools
    ```

2.  **Run the installer:**

    ```bash
    sudo python3 huntools.py install --all
    ```
    *   To install a single tool: `sudo python3 huntools.py install -s <tool_name>`

---

## 💡 Usage

*   **Install all tools:** `huntools install --all`
*   **Install a single tool:** `huntools install -s <tool_name>`
*   **Reinstall a tool:** `huntools reinstall <tool_name>`
*   **Check tool health:** `huntools check -hc`
*   **Display all available tools:** `huntools display --all`
*   **Update all tools:** `huntools update --all`
*   **Update a single tool:** `huntools update -s <tool_name>`
*   **Update huntools itself:** `huntools update --self`
*   **Remove all tools:** `huntools remove --all`
*   **Remove a single tool:** `huntools remove -s <tool_name>`
*   **Purge all huntools data:** `huntools remove --clean`
*   **Show huntools paths:** `huntools show --path`
*   **View changelog:** `huntools show --changelog`

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

```