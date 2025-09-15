# Changelog for augur

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

* Switch to idalib v0.7 and update other dependencies.
* Update documentation.
* Improve output messages.
* Update build and doc GitHub workflows.

## [0.6.2] - 2025-07-18

### Changed

* Update dependencies.

### Fixed

* Update LLVM version in Windows build action.

## [0.6.1] - 2025-06-13

### Added

* Add `ida-plugin.json` for <https://plugins.hex-rays.com/>.

### Changed

* Disable debug info to improve compile time.
* Update dependencies.

## [0.6.0] - 2025-05-23

### Added

* Add contents read permission to build CI.

### Changed

* Switch to idalib v0.6 and update other dependencies.
* Improve documentation.

### Fixed

* Address new clippy lints.

## [0.5.4] - 2025-05-09

### Changed

* Update dependencies.

### Fixed

* Update `sccache-action` version.

## [0.5.3] - 2025-03-29

### Added

* Add `security` category to Cargo.toml.

### Changed

* Refactor the integration test directory structure.
* Update dependencies.

## [0.5.2] - 2025-03-20

### Changed

* Port to the `windows` family and update documentation.
* Update documentation to clarify LLVM/Clang requirement.
* Update dependencies.

### Fixed

* Truncate filenames to handle filesystem limits.
* Handle reserved characters in Windows filenames.
* Fix typo in documentation.

## [0.5.1] - 2025-03-10

### Changed

* Update dependencies.
* Add `missing_docs` lint and improve documentation.
* Avoid generating documentation for private items.
* Improve CI effectiveness and performance.

## [0.5.0] - 2025-03-03

### Changed

* Follow idalib major version from now on.
* Switch to idalib v0.5.1, haruspex v0.5.0, and update other dependencies.
* Update documentation and add a compatibility matrix.
* Make CI more robust for future IDA SDK updates.

### Removed

* Remove the target file check that is no longer necessary.

## [0.2.3] - 2025-02-28

### Changed

* Bump Rust edition to 2024 and update dependencies and CI.
* Switch to idalib v0.4.1 and update other dependencies.
* Improve error handling.
* Improve CI speed by removing redundant tasks.

## [0.2.2] - 2025-02-24

### Changed

* Update dependencies.
* Improve documentation.

## [0.2.1] - 2025-02-19

### Changed

* Update dependencies.
* Improve documentation.

## [0.2.0] - 2025-02-16

### Fixed

* Avoid decompiling functions with the `thunk` attribute, which also fixes a decompiler bug.

## [0.1.2] - 2025-02-13

### Changed

* Refactor code to avoid unwrapping Options.
* Update dependencies.
* Improve documentation.

## [0.1.1] - 2025-02-03

### Changed

* Update dependencies.
* Update documentation.

### Fixed

* Fix comments and output in the integration test.

## [0.1.0] - 2025-01-24

* First release to be published to [crates.io](https://crates.io/).

[unreleased]: https://github.com/0xdea/augur/compare/v0.6.2...HEAD

[0.6.2]: https://github.com/0xdea/augur/compare/v0.6.1...v0.6.2

[0.6.1]: https://github.com/0xdea/augur/compare/v0.6.0...v0.6.1

[0.6.0]: https://github.com/0xdea/augur/compare/v0.5.4...v0.6.0

[0.5.4]: https://github.com/0xdea/augur/compare/v0.5.3...v0.5.4

[0.5.3]: https://github.com/0xdea/augur/compare/v0.5.2...v0.5.3

[0.5.2]: https://github.com/0xdea/augur/compare/v0.5.1...v0.5.2

[0.5.1]: https://github.com/0xdea/augur/compare/v0.5.0...v0.5.1

[0.5.0]: https://github.com/0xdea/augur/compare/v0.2.3...v0.5.0

[0.2.3]: https://github.com/0xdea/augur/compare/v0.2.2...v0.2.3

[0.2.2]: https://github.com/0xdea/augur/compare/v0.2.1...v0.2.2

[0.2.1]: https://github.com/0xdea/augur/compare/v0.2.0...v0.2.1

[0.2.0]: https://github.com/0xdea/augur/compare/v0.1.2...v0.2.0

[0.1.2]: https://github.com/0xdea/augur/compare/v0.1.1...v0.1.2

[0.1.1]: https://github.com/0xdea/augur/compare/v0.1.0...v0.1.1

[0.1.0]: https://github.com/0xdea/augur/releases/tag/v0.1.0
