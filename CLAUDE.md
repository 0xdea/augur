# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**Augur** is an IDA Pro headless plugin (written in Rust) that extracts strings and related pseudocode from binaries. It uses idalib's headless SDK to auto-analyze a binary, finds all string XREFs, decompiles the referencing functions, and writes the pseudocode to a `<binary>.str/` output directory organized by string.

## Build & Test Commands

```bash
# Build (requires IDADIR to be set at runtime, not just compile time)
cargo build --release

# Run all tests (integration test against tests/data/ls binary)
cargo test

# Run the specific integration test
cargo test --test tests

# Lint
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings

# Check semver compatibility
cargo semver-checks
```

The `IDADIR` environment variable must point to the IDA Pro installation directory at **runtime** (not just compile time). The build script checks common installation paths if it's unset, but for non-standard locations it must be set explicitly.

On Windows, `LIBCLANG_PATH` must also be set to the LLVM/Clang bin directory.

## Architecture

This is a **single-crate project** — no workspace, just `src/main.rs` (CLI entry point) and `src/lib.rs` (all core logic).

### Key types and functions

- **`IDAString`**: Wraps a `String` representing one binary string. Has two methods:
  - `traverse_xrefs()`: Iteratively walks the XREF chain; for each non-thunk function, calls `dump_function_pseudocode()` and increments the use count.
  - `filter_printable_chars()`: Returns only ASCII graphic characters and spaces — used to produce a human-readable string before passing to `sanitize_filename()`.

- **`dump_function_pseudocode(idb, func, from, dirpath)`**: Free function that builds the output path via `haruspex::output_path_for_function`, creates the subdirectory, decompiles to file, and prints the result.

- **`run(filepath: &Path) -> anyhow::Result<usize>`**: Public entry point. Opens the binary via `IDB::open()`, calls `haruspex::prepare_output_dir()` to set up the `<binary>.str/` directory, iterates all strings, dispatches `traverse_xrefs()` for each, returns the total decompiled use count.

### Output layout

```
<binary>.str/
  _{addr:X}_{sanitized_string}_/
    {func_name}@{addr}.c
    ...
```

### Error handling

- Uses `anyhow::Result<T>` throughout.
- License errors from Hex-Rays trigger cleanup of the output directory and immediate exit.
- Thunk functions are silently skipped.
- If no string uses are found, the output directory is deleted and an error is returned.

### External dependencies

- **idalib** (0.9): Rust bindings for IDA Pro's idalib (headless SDK).
- **haruspex** (0.9): Decompiler helper; provides `decompile_to_file`, `sanitize_filename`, `output_path_for_function`, and `prepare_output_dir`.
- **anyhow** (1.0): Error handling.
- **idalib-build** (0.9): Build-time linkage configuration (used in `build.rs`).

## Lint policy

Workspace lints in `Cargo.toml` are strict: `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, and similar restriction lints are all denied. Use `anyhow`/`?` for error propagation and `Option` combinators instead.

## Tests

**Unit tests** (`src/lib.rs`, `#[cfg(test)]`): cover `IDAString::filter_printable_chars` — no IDA required, run with `cargo test --lib`.

**Integration test** (`tests/main.rs`): custom harness that runs against `tests/data/ls` (a real Linux `ls` binary) and asserts:
- Exactly 27 decompiled string uses
- Exactly 26 output subdirectories
- A specific total file count in the output tree
- `_905C_write error_/sub_4AD0@4AD0.c` exists and is non-empty (spot-checks naming and decompilation output)

Uses the `walkdir` dev-dependency. Requires a live IDA Pro installation.
