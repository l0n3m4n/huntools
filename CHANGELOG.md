# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2025-10-25

### Added

-   **Docker Image Generation:** Introduced a new `docker` command with a `-g`/`--generate` option to output a `Dockerfile` for creating a Huntools environment. This allows for consistent, isolated, and portable tool management.
-   **Enhanced `remove_single` command:** Added detailed confirmation prompt including tool location, and warnings for system-protected directories requiring `sudo`.
-   **Case-insensitive tool lookup:** Implemented case-insensitive matching for tool names in `remove_single` command.
-   **Confirmation prompts for `remove -ra` and `remove -ca`:** Added interactive confirmation steps for bulk removal and purging of Huntools data.
-   **Colorized output for `show_path`:** Improved readability of path information with distinct colors for labels and paths.
-   **Colorized installation messages:** Enhanced visual feedback during `install_dependencies` and `install_all` processes.

### Changed

-   **Command-line argument aliases:** Standardized short and long options for `update`, `remove`, `display`, `show`, and `config` commands, with hidden aliases for cleaner help output.
-   **Banner version:** Updated Huntools version to `3.0.0`.
-   **`display` command help message:** Improved clarity of the `display` command's help message.
-   **`config` command argument names:** Changed `-p` to `-cp` for custom path.

### Fixed

-   `UnboundLocalError` in `remove_single` function due to conditional `warning_message` initialization.
-   `IndentationError` in `remove_all` function.
-   `==SUPPRESS==` display in `display` command's help output.

## [2.0.0] - 2025-10-25

### Added

-   Initial project setup.
-   Core functionality for installing, updating, and removing bug hunting tools.
-   Support for Go, Python (pip & git), system packages, and generic Git repositories.
-   `display`, `check`, `show`, and `config` commands.
-   Graceful `Ctrl+C` handling for user interruptions.
-   Checksum verification for Go tool downloads.
-   Detection and repair of incomplete Git clones.
-   `reinstall` command for easy tool reinstallation.
-   Dynamic tool count in the banner.
-   Improved error messages for not-found tools.

### Changed

-   Refactored tool management to use a unified `ALL_TOOLS` dictionary for better scalability and maintainability.
-   Updated `README.md` to reflect all new features and usage.
-   Changed `check` command flag from `--health` to `-hc`.
-   Improved help message formatting for `install` command.
-   Updated banner text to "Hunter's Arsenal".

### Fixed

-   `NameError` in `install_single` due to old tool list references.
-   `IndentationError` in error messages for `install_single`, `remove_single`, and `update_single`.