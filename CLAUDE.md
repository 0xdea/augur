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

- **`DumpCache`**: Type alias for `HashMap<Address, Option<DumpedFunction>>`, keyed by function start address and shared across all strings. `None` records a function that failed to decompile, so it is not retried.

- **`DumpedFunction`**: Records the output files of a decompiled function: the most recently written `.c` path (`source`) and whether a sibling `.h` was written (`has_header`). Has two methods:
  - `decompile_to(idb, func, dirpath, output_path) -> Result<Option<Self>, HaruspexError>`: Decompiles the function via `idb.decompile()` and writes the output files via haruspex's `dump_cfunc_pseudocode_to_file` and `dump_cfunc_types_to_file`. The string's subdirectory is only created once there is something to write, so no empty directories are left behind. Type definitions are best-effort: on `HaruspexError::TypesEmpty` or a non-license error while dumping them, only the `.c` file is written. Returns `Ok(None)` if the function can't be decompiled; Hex-Rays license errors are propagated.
  - `copy_to(dirpath, output_path) -> io::Result<()>`: Copies the output files into another string's directory with `fs::copy`, then points `source` at the new copy. Does nothing if the files are already in place (including right after `decompile_to`).

- **`dump_function_pseudocode(idb, func, from, dirpath, dumped) -> Result<bool, HaruspexError>`**: Free function that builds the output path via `haruspex::output_path_for_function`, makes the function's output files available in `dirpath`, and prints the result (the printed line omits the header path when there is no `.h`). Each function is decompiled at most once per run, tracked by the `dumped` `DumpCache`. On first use, the entry is filled with `DumpedFunction::decompile_to()`; then `DumpedFunction::copy_to()` is called unconditionally, and copies the files only if they were dumped for another string. Returns `true` if the pseudocode was dumped; returns `false` and prints `{from:#X} in {func_name} -> [decompilation failed]` if the function can't be decompiled. Since all uses of one string are handled in a single `traverse_xrefs()` call, repeated uses within a string never copy the files twice. This matters because idalib decompiles with `DECOMP_NO_CACHE`, so every `decompile()` call is a full decompilation.

- **`traverse_xrefs(idb, first_xref, dirpath, dumped) -> Result<usize, HaruspexError>`**: Free function that iteratively walks the XREF chain to one string; for each non-thunk function, calls `dump_function_pseudocode()` into the string's subdirectory `dirpath`, and returns the number of calls that returned `true`. A function that fails to decompile is skipped without affecting the string's other XREFs.

- **`recover_strings(idb: &mut IDB) -> Result<(), IDAError>`**: Free function that decompiles every non-thunk function upfront, discarding the output, to let IDA 9.4's decompiler recover additional strings. Then calls `idb.auto_wait()` (printing a warning if it returns `false`) followed by `idb.strings().rebuild()`. The decompiler only queues the new string items for auto-analysis, so without `auto_wait()` the rebuilt string list would not include them; keep these three steps together and in this order. Returns early with the error on a Hex-Rays license error; ignores all other decompilation errors.

- **`extract_string_uses(idb: &mut IDB, dirpath) -> anyhow::Result<usize>`**: Free function holding all the work that writes into the output directory. Calls `recover_strings()`, then iterates `idb.strings().iter()` (which skips invalid entries in the string list), and for each string with at least one XREF builds its subdirectory name `_{addr:X}_{sanitized_string}_` (via `filter_printable_chars()` and `sanitize_filename()`) and dispatches `traverse_xrefs()`, summing the returned counts with `saturating_add`. Returns an error if no string uses were found.

- **`run(filepath: impl AsRef<Path>) -> anyhow::Result<usize>`**: Public entry point. Opens the binary via `IDB::open()`, disables the Hex-Rays argument name hints via `idb.modify_decompiler_config(ArgHintsMode::Disabled.directive())` (before any decompilation, so that every decompilation, including the `recover_strings()` pre-pass, picks up the config change), calls `haruspex::prepare_output_dir()` to set up the `<binary>.str/` directory (before the slow pre-pass, so an existing non-empty directory fails fast), then calls `extract_string_uses()` and returns its total use count. This is the single cleanup point: if `extract_string_uses()` returns any error (including no string uses found), the output directory is removed and the original error is returned; if removing the directory fails too, a warning is printed to stderr. Informational/progress messages go to stderr; only the per-string and per-function result lines (address, name, output path) go to stdout. Prints total elapsed time on completion.

- **`is_license_error(err: &IDAError) -> bool`**: Returns `true` for a Hex-Rays license error. Used by every place that must stop on license errors while ignoring other decompilation errors. Matching `&IDAError` relies on default binding modes, which is why `clippy::pattern_type_mismatch` is allowed in `Cargo.toml`.

- **`filter_printable_chars(string: &str) -> String`**: Returns only ASCII graphic characters and spaces — used to produce a human-readable string before passing to `sanitize_filename()`.

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
- Any error after the output directory is created (including Hex-Rays license errors and I/O errors) removes the output directory and exits with that error. `run()` is the only place that performs this cleanup.
- Thunk functions are silently skipped.
- Functions that fail to decompile are reported on stdout, skipped (not counted as string uses), and not retried.
- If no string uses are found, the output directory is deleted and an error is returned.

### External dependencies

- **idalib** (0.10): Rust bindings for IDA's idalib (headless SDK).
- **haruspex** (0.10.1 or later): Decompiler helper; provides `dump_cfunc_pseudocode_to_file`, `dump_cfunc_types_to_file` (both added in 0.10.1), `sanitize_filename`, `output_path_for_function`, and `prepare_output_dir`.
- **anyhow** (1.0): Error handling.
- **idalib-build** (0.10): Build-time linkage configuration (used in `build.rs`).

## Lint policy

All clippy lint groups (`all`, `pedantic`, `nursery`, `cargo`, `restriction`) are enabled as warnings in `Cargo.toml` and treated as errors by `cargo clippy -- -D warnings`. A small set of restriction lints are explicitly allowed (e.g. `implicit_return`, `question_mark_used`, `print_stdout`, `pattern_type_mismatch`). Use `anyhow`/`?` for error propagation and `Option` combinators instead of `unwrap`/`expect`. When a restriction lint must be suppressed, use `#[expect(..., reason = "...")]` rather than `#[allow(...)]`.

## Tests

**Unit tests** (`src/lib.rs`, `#[cfg(test)]`): cover `filter_printable_chars`.

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
