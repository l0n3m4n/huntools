# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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