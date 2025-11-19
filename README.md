<p align="center">
  <img src="./assets/logo.png" alt="Logo" width="300" />
</p>
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
- ⚙️ **Configuration Validation:** Implemented validation for `config.yml` to ensure correct paths and values, improving script robustness.
- ⚡ **Parallel Installation:** Enhanced `install_multiple` and `install_all` functions to use `ThreadPoolExecutor` for concurrent tool installations, significantly speeding up the process.
- 🚨 **Improved Error Reporting:** Added timestamps to error logs and included a comprehensive installation summary in `errors.log` for better debugging.
- 📄 **Flexible Output Formats:** Extended the `display` command with a `--format json` option to output the list of available tools in JSON format.
- 🧪 **Automated Testing:** Introduced a `pytest` test suite with initial tests for configuration validation, ensuring code quality.
- 🚀 **CI/CD Integration:** Added a GitHub Actions workflow (`.github/workflows/ci.yml`) to automatically run tests on push and pull requests, streamlining development.

---

![banner](assets/banner.png) 
<img src="assets/huntools1.png" style="margin:0;padding:0;display:inline-block;vertical-align:middle;">
<img src="assets/huntools2.png" style="margin:0;padding:0;display:inline-block;vertical-align:middle;">

---
