# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [3.5.0] - 2025-11-19

### Added
- **Configuration Validation:** Implemented validation for `config.yml` to ensure correct paths and values, improving script robustness.
- **Parallel Installation:** Enhanced `install_multiple` and `install_all` functions to use `ThreadPoolExecutor` for concurrent tool installations, significantly speeding up the process.
- **Improved Error Reporting:** Added timestamps to error logs and included a comprehensive installation summary in `errors.log` for better debugging.
- **JSON Output Format:** Extended the `display` command with a `--format json` option to output the list of available tools in JSON format.
- **Automated Testing:** Introduced a `pytest` test suite with initial tests for configuration validation.
- **CI/CD Integration:** Added a GitHub Actions workflow (`.github/workflows/ci.yml`) to automatically run tests on push and pull requests.

### Changed
- Updated version to 3.5.0.


## [3.4.2] - 2025-11-06

### Added
- `install -m` or `install --multiple` for installing multiple tools at once, separated by commas.

### Changed
- Updated version to 3.4.2.


## [3.4.0] - 2025-10-31

### Added
- User prompt for large Python tools: Implemented a confirmation prompt before installing large Python tools (e.g., `seclists`, `subwiz`) to allow users to skip them.
- Poetry installation: Added automatic installation of Poetry as a system dependency.

### Changed
- Shodan installation: Corrected the GitHub repository URL for Shodan.
- Python tools installation: Modified the `install_python_tools` function to install `python_git` tools using Poetry.
- Go tools installation: Changed `urless`, `xnLinkFinder`, `xnldorker`, and `porch-pirate` to be installed as `go` type tools, executing `pip install git+...` commands directly.
- Feroxbuster installation: Updated the installation method to use `curl` for direct binary download and installation.
- Trufflehog installation: Added `rm -rf` for the temporary directory to prevent `git clone` errors.
- Health check: Improved `checking_health` function to be case-insensitive and correctly identify `go` tools installed in `$HOME/.huntools/go`.

### Removed
- `setup.py` installation: Removed the deprecated `setup.py` installation method for Python tools.

### Fixed
- `trufflehog` installation: Resolved `git clone` error by adding `rm -rf` for the temporary directory.
- `massdns` installation: Resolved `git clone` error by adding `rm -rf` for the temporary directory.
- `pydictor` syntax error: Removed a stray `git clone` command from the `ALL_TOOLS` dictionary.
- `wafw00f` installation: Added `python3-setuptools` to system dependencies to resolve `ModuleNotFoundError`.
- `p1radup` installation: Changed to manual installation due to permission issues with `setup.py install`.


## [3.3.0] - 2025-10-26

### Added
- System-wide installation feature (`install -is` or `install --install-system`) to install `huntools` to `/usr/local/bin`.
- Documentation for the new system-wide installation feature in `README.md`.

### Changed
- The `remove -ca` (`clean_all`) command now also removes the system-wide `huntools` executable if it exists.

## [3.2.0] - 2025-10-26

### Added

- **`show` Command Help Display:** Modified `huntools.py show` to automatically display its help menu if no specific arguments are provided, improving user guidance.
- `AttributeError: 'Namespace' object has no attribute 'force_remove'` when using `reinstall` command by adding `--force` argument to the `reinstall` subparser.
- **Changelog Display Empty Sections:** Refined `show_changelog` Markdown parsing logic to correctly display content under sub-headings (e.g., `### Added`), empty lines, and general text, resolving issues where sections appeared empty in the terminal output.
- **H3 Sub-heading Display:** Corrected `show_changelog` to remove the `### ` prefix from sub-headings (e.g., "Added", "Changed", "Fixed") for a cleaner terminal output.
- **Enhanced Markdown Rendering for Changelog:** Improved `show_changelog` to render Markdown headings, bold text, and inline code blocks with ANSI colors for a more professional and readable terminal output.
- **Enhanced H1 Heading Rendering:** Implemented bold and red coloring for H1 headings (`#`) in the changelog display for improved visibility and professionalism.
- **Italics Support in Changelog:** Enhanced `show_changelog` to render Markdown italics (`*text*` and `_text_`) with ANSI colors for improved readability.
- `--force` option for removal commands: Added a `-f`/`--force` argument to `remove`, `reinstall`, and `clean` commands to bypass confirmation prompts.

### Changed

- **Force Removal Warning Suppression:** Corrected `remove_single` to properly suppress the warning message and confirmation prompt when the `--force` (`-f`) flag is used, providing a green colorized message for force removal initiation.
- **Go Tool Removal:** Refactored `remove_single` function to robustly locate and remove Go tool executables by prioritizing the configured Go binary directory, resolving "not found in GOPATH or PATH for removal" errors.
- **Improved Command Help Display:** Modified `install`, `update`, `remove`, `display`, `check`, `config`, and `docker` commands to automatically display their respective help menus if invoked without specific arguments, enhancing user guidance.
- **Dynamic Configuration File Path:** Implemented dynamic loading and saving of the configuration file, allowing users to specify a custom path for `config.ini` which persists across sessions.
- **Go Environment Variable Configuration:** Enhanced `install_go` to automatically configure Go environment variables in `~/.bashrc`, `~/.zshrc`, and `~/.profile`, preventing duplicate entries. Added specific manual instructions for `fish` shell users.

## [3.1.0] - 2025-10-26

### Added

- Persistent configuration: Implemented `configparser` to save and load custom installation paths (`install_dir`, `go_bin_dir`, `python_dir`, `git_dir`).

### Changed

- `install_go`, `install_python_tools`, `install_git_repos`, `get_tool_location_and_command`, `show_path`, `remove_all`, and `clean_all` functions now utilize persistent configuration paths.

### Fixed

- `update_all` function: Corrected to iterate through `ALL_TOOLS` and use appropriate update logic for each tool type, resolving `NameError` due to undefined variables.
- `remove_all` function: Corrected to iterate through `ALL_TOOLS` and use `remove_single` for each tool, resolving `NameError` due to undefined variables.
- Go environment variables: Modified `install_go` to prevent duplicate entries in `~/.bashrc`.

## [3.0.0] - 2025-10-25

### Added

- **Docker Image Generation:** Introduced a new `docker` command with a `-g`/`--generate` option to output a `Dockerfile` for creating a Huntools environment. This allows for consistent, isolated, and portable tool management.
- **Enhanced `remove_single` command:** Added detailed confirmation prompt including tool location, and warnings for system-protected directories requiring `sudo`.
- **Case-insensitive tool lookup:** Implemented case-insensitive matching for tool names in `remove_single` command.
- **Confirmation prompts for `remove -ra` and `remove -ca`:** Added interactive confirmation steps for bulk removal and purging of Huntools data.
- **Colorized output for `show_path`:** Improved readability of path information with distinct colors for labels and paths.
- **Colorized installation messages:** Enhanced visual feedback during `install_dependencies` and `install_all` processes.

### Changed

- **Command-line argument aliases:** Standardized short and long options for `update`, `remove`, `display`, `show`, and `config` commands, with hidden aliases for cleaner help output.
- **Banner version:** Updated Huntools version to `3.0.0`.
- **`display` command help message:** Improved clarity of the `display` command's help message.
- **`config` command argument names:** Changed `-p` to `-cp` for custom path.

### Fixed

- `UnboundLocalError` in `remove_single` function due to conditional `warning_message` initialization.
- `IndentationError` in `remove_all` function.
- `==SUPPRESS==` display in `display` command's help output.

## [2.0.0] - 2025-10-25

### Added

- Initial project setup.
- Core functionality for installing, updating, and removing bug hunting tools.
- Support for Go, Python (pip & git), system packages, and generic Git repositories.
- `display`, `check`, `show`, and `config` commands.
- Graceful `Ctrl+C` handling for user interruptions.
- Checksum verification for Go tool downloads.
- Detection and repair of incomplete Git clones.
- `reinstall` command for easy tool reinstallation.
- Dynamic tool count in the banner.
- Improved error messages for not-found tools.

### Changed

- Refactored tool management to use a unified `ALL_TOOLS` dictionary for better scalability and maintainability.
- Updated `README.md` to reflect all new features and usage.
- Changed `check` command flag from `--health` to `-hc`.
- Improved help message formatting for `install` command.
- Updated banner text to "Hunter's Arsenal".

### Fixed

- `NameError` in `install_single` due to old tool list references.
- `IndentationError` in error messages for `install_single`, `remove_single`, and `update_single`.

## [1.0.0] - 2025-10-24

### Added

- Initial project setup.