# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**Augur** is an IDA headless plugin (written in Rust) that extracts strings and related pseudocode from binaries. It uses idalib's headless SDK to auto-analyze a binary, finds all string XREFs, decompiles the referencing functions, and writes the pseudocode to a `<binary>.str/` output directory organized by string.

## Build & Test Commands

```bash
# Build (requires IDADIR to be set at runtime, not just compile time)
cargo build --release --locked

# Run all tests (integration test against tests/data/dox_sig_parser binary)
cargo test --locked

# Run the specific integration test
cargo test --test tests --locked

# Lint
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings

# Check for known-vulnerable dependencies
cargo audit

# Check docs build cleanly (CI treats warnings as errors here too)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked

# Check semver compatibility
cargo semver-checks
```

The `IDADIR` environment variable must point to the IDA installation directory at **runtime** (not just compile time). The build script checks common installation paths if it's unset, but for non-standard locations it must be set explicitly.

On Windows, `LIBCLANG_PATH` must also be set to the LLVM/Clang bin directory.

## Architecture

This is a **single-crate project** — no workspace, just `src/main.rs` (CLI entry point) and `src/lib.rs` (all core logic).

### Key types and functions

- **`IDAString`**: Wraps a `String` representing one binary string. Has two methods:
  - `traverse_xrefs()`: Iteratively walks the XREF chain; for each non-thunk function, calls `dump_function_pseudocode()` and increments the use count.
  - `filter_printable_chars()`: Returns only ASCII graphic characters and spaces — used to produce a human-readable string before passing to `sanitize_filename()`.

- **`dump_function_pseudocode(idb, func, from, dirpath)`**: Free function that builds the output path via `haruspex::output_path_for_function`, creates the subdirectory, decompiles to file, and prints the result. Writes a `.c` pseudocode file plus a sibling `.h` file with type definitions when any exist; if `decompile_to_file` returns `HaruspexError::TypesEmpty` (no type defs to dump), only the `.c` file is written and the printed line omits the header path. Each function is decompiled at most once per run: a `HashMap<Address, DumpedFunction>` (keyed by function start address, shared across all strings) records the most recently written `.c` path and whether a `.h` was written (checked on disk via `header_path.is_file()`, because haruspex's `decompile_to_file` returns `Ok(())` even when dumping type definitions failed with a non-license IDA error); later uses of the same function are skipped if the output is already in place, or copied with `fs::copy` into the new string's directory, after which the entry points at the new copy. This relies on all uses of one string being handled in a single `traverse_xrefs()` call, so repeated uses within a string are never copied twice. This matters because idalib decompiles with `DECOMP_NO_CACHE`, so every `decompile()` call is a full decompilation.

- **`recover_strings(idb: &mut IDB) -> Result<(), IDAError>`**: Free function that decompiles every non-thunk function upfront, discarding the output, to let IDA 9.4's decompiler recover additional strings. Then calls `idb.auto_wait()` (printing a warning if it returns `false`) followed by `idb.strings().rebuild()`. The decompiler only queues the new string items for auto-analysis, so without `auto_wait()` the rebuilt string list would not include them; keep these three steps together and in this order. Returns early with the error on a Hex-Rays license error; ignores all other decompilation errors.

- **`run(filepath: impl AsRef<Path>) -> anyhow::Result<usize>`**: Public entry point. Opens the binary via `IDB::open()`, disables the Hex-Rays argument name hints via `idb.modify_decompiler_config(ArgHintsMode::Disabled.directive())` (before any decompilation, since Hex-Rays caches decompiled functions), calls `haruspex::prepare_output_dir()` to set up the `<binary>.str/` directory (before the slow pre-pass, so an existing non-empty directory fails fast), calls `recover_strings()` (removing the output directory on error), then iterates all strings, dispatches `traverse_xrefs()` for each, returns the total decompiled use count. Informational/progress messages go to stderr; only the per-string and per-function result lines (address, name, output path) go to stdout. Prints total elapsed time on completion.

### Output layout

```
<binary>.str/
  _{addr:X}_{sanitized_string}_/
    {func_name}@{addr}.c
    {func_name}@{addr}.h   # only when the function has type definitions to dump
    ...
```

### Error handling

- Uses `anyhow::Result<T>` throughout.
- License errors from Hex-Rays trigger cleanup of the output directory and immediate exit.
- Thunk functions are silently skipped.
- If no string uses are found, the output directory is deleted and an error is returned.

### External dependencies

- **idalib** (0.10): Rust bindings for IDA's idalib (headless SDK).
- **haruspex** (0.10): Decompiler helper; provides `decompile_to_file`, `sanitize_filename`, `output_path_for_function`, and `prepare_output_dir`.
- **anyhow** (1.0): Error handling.
- **idalib-build** (0.10): Build-time linkage configuration (used in `build.rs`).

## Lint policy

All clippy lint groups (`all`, `pedantic`, `nursery`, `cargo`, `restriction`) are enabled as warnings in `Cargo.toml` and treated as errors by `cargo clippy -- -D warnings`. A small set of restriction lints are explicitly allowed (e.g. `implicit_return`, `question_mark_used`, `print_stdout`). Use `anyhow`/`?` for error propagation and `Option` combinators instead of `unwrap`/`expect`. When a restriction lint must be suppressed, use `#[expect(..., reason = "...")]` rather than `#[allow(...)]`.

## Tests

**Unit tests** (`src/lib.rs`, `#[cfg(test)]`): cover `IDAString::filter_printable_chars`.

**Integration test** (`tests/main.rs`): custom harness that runs against `tests/data/dox_sig_parser` and asserts:

- Exactly 18 decompiled string uses (only 5 without the `recover_strings()` pre-pass)
- Exactly 10 output subdirectories
- A specific total file count in the output tree (subdirectories + `.c` files + `.h` files + the root; several uses in the same function share one `.c` file)
- `_4020A8_Parsing type error at line %d__/` exists and is non-empty (regression test for `recover_strings()`: this string's uses are only found after decompiling all functions upfront)
- `_402108__atoi_/sub_401B00@401B00.c` does not contain Hex-Rays argument name hints (regression test for the hints-disabled default)
- `_4020C8_type ERROR_/sub_400C80@400C80.c` exists and is non-empty (spot-checks naming and decompilation output)
- `_4020C8_type ERROR_/sub_401750@401750.h` does not exist (regression test for the `TypesEmpty` case: no header when there are no type defs)
- `_4020C8_type ERROR_/sub_400C80@400C80.h` exists and is non-empty (regression test for the normal case: header written alongside the `.c` file)

Test harness progress messages are printed to stderr.

Uses the `walkdir` dev-dependency. Requires a live IDA installation.
