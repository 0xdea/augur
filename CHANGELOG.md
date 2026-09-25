# Changelog for augur

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Decompile each function only once, reusing its output files for further string uses.
- Don't retry decompiling functions that already failed to decompile.
- Report functions that fail to decompile in tool output.
- Require haruspex v0.10.1 or later.
- Improve code style.

### Fixed

- Skip invalid entries in the string list instead of aborting the whole run.
- Remove trailing whitespace from the string lines in tool output.
- Keep processing the other uses of a string when one of the referencing functions fails to decompile.
- Don't leave empty directories behind for strings whose referencing functions all fail to decompile.
- Remove the partially populated output directory on any error, not only on Hex-Rays license errors.

## [0.10.2] - 2026-09-24

### Added

- Add an upfront full decompilation step to allow IDA 9.4 to [recover additional strings](https://docs.hex-rays.com/release-notes/9_4#decompiler-strings).
- Add regression tests for additional string recovery via the decompiler.

### Changed

- Update documentation.
- Update dependencies.

### Fixed

- Fix missing string use location in tool output.
- Fix link to `CHANGELOG.md`.

## [0.10.1] - 2026-09-21

### Added

- Display elapsed time in the `run` function.
- Dump type definitions used by a decompiled function to a sibling `.h` file, when available.
- Add regression tests for the presence/absence of the `.h` file depending on whether type definitions are available.

### Changed

- Move informational messages to `stderr`.
- Use `CARGO_BIN_NAME` instead of `CARGO_PKG_NAME` for the program name.
- Update documentation.
- Update dependencies.

### Fixed

- Account for recent changes in the haruspex library API (v0.10.1).

## [0.10.0] - 2026-09-18

### Added

- Disable the new argument name hints in the Hex-Rays decompiler.
- Add a regression test to check that argument name hints are not present in the extracted pseudocode.
- Add credits section to `README.md`.

### Changed

- Update idalib to v0.10.1 and haruspex to v0.10.0 to support IDA 9.4.
- Update other dependencies.
- Use `AsRef<Path>` bounds for all public functions that take a `Path` argument.
- Enable all clippy restriction lints and fix any resulting issues.
- Use the `--locked` flag for all suitable `cargo` commands.
- Improve comments.
- Improve unit tests.
- Improve CI.
- Update documentation.

### Fixed

- Allow linker messages to prevent Windows build from failing.

## [0.9.3] - 2026-06-06

### Changed

- Update documentation.
- Update dependencies.

## [0.9.2] - 2026-06-01

### Added

- Add unit tests for helper functions.
- Add an integration test to check naming and decompilation functionalities.

### Changed

- Extract `dump_function_pseudocode` helper function.
- Use the new helper functions exported by hauruspex 0.9.3 to simplify the codebase.
- Use workspace lints and add some lints in the `clippy::restriction` category.
- Improve documentation.
- Update dependencies.
- Fix some zizmor lints and update CI accordingly.
- Update `mozilla-actions/sccache-action` in CI.

### Fixed

- Refactor `traverse_xrefs` and make it iterative to avoid potential stack overflows with large XREF chains.

## [0.9.1] - 2026-04-24

### Changed

- Compatibility release for IDA 9.3sp2.
- Update documentation.
- Update dependencies.

## [0.9.0] - 2026-04-15

### Added

- Add `semver-checks` to GitHub workflows to enforce semantic versioning.

### Changed

- Update idalib to v0.9.0 to support IDA 9.3sp1.
- Update IDA plugin stub and metadata.
- Improve integration tests and documentation.
- Update other dependencies.

### Fixed

- Fix CHANGELOG link in `README.md`.
- Fix doc workflow.

### Security

- Pin action references to hashes and disable credential persistence in GitHub workflows.

## [0.8.1] - 2026-03-14

### Changed

- Update idalib to v0.8.1 to fix Windows cross-compiling [bug](https://github.com/idalib-rs/idalib/issues/60).
- Update other dependencies.
- Update documentation.
- Small stylistic changes.

## [0.8.0] - 2026-02-20

### Added

- Enable some lints in the `clippy::restriction` category.

### Changed

- Apply idalib-rust-style guidelines.
- Optimize release profile options.
- Improve doc comments.
- Update documentation.
- Update idalib to v0.8.0 and update other dependencies.

## [0.7.5] - 2026-02-04

### Added

- Introduce the `AUTHORS` constant.

### Changed

- Use a local counter instead of a global atomic.
- Move the call to `filter_printable_chars` out of the XREF loop to improve performance.
- Avoid calling `idb.strings` repeatedly to improve performance.
- Improve command line parsing, error handling, and usage messages.
- Replace `<unknown>` with `[unknown]` to avoid using reserved chars.
- Improve message wording and documentation.
- Improve doc comments.
- Update links to the idalib-rs repository.
- Update dependencies.

### Fixed

- Add a `_` prefix/suffix to `output_dir` to address this [issue](https://github.com/0xdea/augur/issues/1).
- Replace `<no name>` with `[no name]` to avoid using reserved chars.

## [0.7.4] - 2025-12-05

### Changed

- Use idiomatic `anyhow` macros for early returns.
- Replace `static` with `const` where appropriate.
- Include `README.md` as the crate documentation to avoid writing it twice.
- Update copyright notice.
- Update dependencies.

### Fixed

- Update `urls` in `ida-plugin.json`.

## [0.7.3] - 2025-11-15

### Added

- Add an `ida-plugin-stub.py` as a workaround for this [issue](https://github.com/HexRaysSA/ida-hcli/issues/114).

### Changed

- Update `ida-plugin.json` to comply with the
  new [IDA Plugin Repository](https://hcli.docs.hex-rays.com/reference/packaging-your-existing-plugin/).
- Update dependencies.

## [0.7.2] - 2025-10-13

### Changed

- Improve documentation.
- Update dependencies.

## [0.7.1] - 2025-09-17

### Changed

- Update idalib to v0.7.2 and update other dependencies.

## [0.7.0] - 2025-09-15

### Changed

- Switch to idalib v0.7 and update other dependencies.
- Update documentation.
- Improve output messages.
- Update build and doc GitHub workflows.

## [0.6.2] - 2025-07-18

### Changed

- Update dependencies.

### Fixed

- Update LLVM version in Windows build action.

## [0.6.1] - 2025-06-13

### Added

- Add `ida-plugin.json` for <https://plugins.hex-rays.com/>.

### Changed

- Disable debug info to improve compile time.
- Update dependencies.

## [0.6.0] - 2025-05-23

### Added

- Add contents read permission to build CI.

### Changed

- Switch to idalib v0.6 and update other dependencies.
- Improve documentation.

### Fixed

- Address new clippy lints.

## [0.5.4] - 2025-05-09

### Changed

- Update dependencies.

### Fixed

- Update `sccache-action` version.

## [0.5.3] - 2025-03-29

### Added

- Add `security` category to Cargo.toml.

### Changed

- Refactor the integration test directory structure.
- Update dependencies.

## [0.5.2] - 2025-03-20

### Changed

- Port to the `windows` family and update documentation.
- Update documentation to clarify LLVM/Clang requirement.
- Update dependencies.

### Fixed

- Truncate filenames to handle filesystem limits.
- Handle reserved characters in Windows filenames.
- Fix typo in documentation.

## [0.5.1] - 2025-03-10

### Changed

- Update dependencies.
- Add `missing_docs` lint and improve documentation.
- Avoid generating documentation for private items.
- Improve CI effectiveness and performance.

## [0.5.0] - 2025-03-03

### Changed

- Follow idalib major version from now on.
- Switch to idalib v0.5.1, haruspex v0.5.0, and update other dependencies.
- Update documentation and add a compatibility matrix.
- Make CI more robust for future IDA SDK updates.

### Removed

- Remove the target file check that is no longer necessary.

## [0.2.3] - 2025-02-28

### Changed

- Bump Rust edition to 2024 and update dependencies and CI.
- Switch to idalib v0.4.1 and update other dependencies.
- Improve error handling.
- Improve CI speed by removing redundant tasks.

## [0.2.2] - 2025-02-24

### Changed

- Update dependencies.
- Improve documentation.

## [0.2.1] - 2025-02-19

### Changed

- Update dependencies.
- Improve documentation.

## [0.2.0] - 2025-02-16

### Fixed

- Avoid decompiling functions with the `thunk` attribute, which also fixes a decompiler bug.

## [0.1.2] - 2025-02-13

### Changed

- Refactor code to avoid unwrapping Options.
- Update dependencies.
- Improve documentation.

## [0.1.1] - 2025-02-03

### Changed

- Update dependencies.
- Update documentation.

### Fixed

- Fix comments and output in the integration test.

## [0.1.0] - 2025-01-24

- First release to be published to [crates.io](https://crates.io/).

[unreleased]: https://github.com/0xdea/augur/compare/v0.10.2...HEAD
[0.10.2]: https://github.com/0xdea/augur/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/0xdea/augur/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/0xdea/augur/compare/v0.9.3...v0.10.0
[0.9.3]: https://github.com/0xdea/augur/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/0xdea/augur/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/0xdea/augur/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/0xdea/augur/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/0xdea/augur/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/0xdea/augur/compare/v0.7.5...v0.8.0
[0.7.5]: https://github.com/0xdea/augur/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/0xdea/augur/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/0xdea/augur/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/0xdea/augur/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/0xdea/augur/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/0xdea/augur/compare/v0.6.2...v0.7.0
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
