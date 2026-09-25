# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**Augur** is an IDA headless plugin (written in Rust) that extracts strings and related pseudocode from binaries. It uses idalib's headless SDK to auto-analyze a binary, finds all string XREFs, decompiles the referencing functions, and writes the pseudocode to a `<binary>.str/` output directory organized by string.

## Build & Test Commands

```bash
# Build (requires IDADIR to be set at runtime, not just compile time)
cargo build --release --locked

# Run all tests (integration tests against tests/data/dox_sig_parser and tests/data/no_strings binaries)
cargo test --locked

# Run only the integration tests
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
  - `decompile_to(idb, func, output_path) -> Result<Option<Self>, HaruspexError>`: Decompiles the function via `idb.decompile()` and writes the output files via haruspex's `dump_cfunc_pseudocode_to_file` and `dump_cfunc_types_to_file`. The string's subdirectory (the parent of `output_path`, created via `create_parent_dir()`) is only created once there is something to write, so no empty directories are left behind. Type definitions are best-effort: on `HaruspexError::TypesEmpty` or a non-license error while dumping them, only the `.c` file is written. Returns `Ok(None)` if the function can't be decompiled; Hex-Rays license errors are propagated.
  - `copy_to(output_path) -> io::Result<()>`: Copies the output files into another string's directory (created via `create_parent_dir()` if missing) with `fs::copy`, then points `source` at the new copy. Does nothing if the files are already in place (including right after `decompile_to`).

- **`dump_function_pseudocode(idb, func, from, dirpath, dumped) -> Result<bool, HaruspexError>`**: Free function that builds the output path via `haruspex::output_path_for_function`, makes the function's output files available in `dirpath`, and prints the result (the printed line omits the header path when there is no `.h`). Each function is decompiled at most once per run, tracked by the `dumped` `DumpCache`. On first use, the entry is filled with `DumpedFunction::decompile_to()`; then `DumpedFunction::copy_to()` is called unconditionally, and copies the files only if they were dumped for another string. Returns `true` if the pseudocode was dumped; returns `false` and prints `{from:#X} in {func_name} -> [decompilation failed]` if the function can't be decompiled. Since all uses of one string are handled in a single `traverse_xrefs()` call, repeated uses within a string never copy the files twice. This matters because idalib decompiles with `DECOMP_NO_CACHE`, so every `decompile()` call is a full decompilation.

- **`traverse_xrefs(idb, addr, dirpath, dumped) -> Result<usize, HaruspexError>`**: Free function that iteratively walks the XREF chain to the string at `addr` with `iter::successors(idb.first_xref_to(addr, XRefQuery::ALL), XRef::next_to)`; for each non-thunk function, calls `dump_function_pseudocode()` into the string's subdirectory `dirpath`, and returns the number of calls that returned `true`. A function that fails to decompile is skipped without affecting the string's other XREFs.

- **`recover_strings(idb: &mut IDB) -> Result<(), IDAError>`**: Free function that decompiles every non-thunk function upfront, discarding the output, to let IDA 9.4's decompiler recover additional strings. Then calls `idb.auto_wait()` (printing a warning if it returns `false`) followed by `idb.strings().rebuild()`. The decompiler only queues the new string items for auto-analysis, so without `auto_wait()` the rebuilt string list would not include them; keep these three steps together and in this order. Returns early with the error on a Hex-Rays license error; ignores all other decompilation errors.

- **`extract_string_uses(idb: &mut IDB, dirpath) -> anyhow::Result<usize>`**: Free function holding all the work that writes into the output directory. Calls `recover_strings()`, then iterates `idb.strings().iter()` (which skips invalid entries in the string list), and for each string builds its subdirectory path via `string_dirname()` and dispatches `traverse_xrefs()` (the subdirectory is only created if something is written in it), summing the returned counts with `saturating_add`. Returns an error if no string uses were found.

- **`run(filepath: impl AsRef<Path>) -> anyhow::Result<usize>`**: Public entry point. Converts `filepath` once with `as_ref()`, then opens the binary via `IDB::open()`, disables the Hex-Rays argument name hints via `idb.modify_decompiler_config(ArgHintsMode::Disabled.directive())` (before any decompilation, so that every decompilation, including the `recover_strings()` pre-pass, picks up the config change), calls `haruspex::prepare_output_dir()` to set up the `<binary>.str/` directory, then calls `extract_string_uses()` and returns its total use count. `prepare_output_dir()` must stay before `extract_string_uses()` and outside the cleanup: this makes an existing non-empty directory fail fast, before the slow pre-pass, and ensures the cleanup never deletes a pre-existing directory with the user's previous results. This is the single cleanup point: if `extract_string_uses()` returns any error (including no string uses found), the output directory is removed and the original error is returned; if removing the directory fails too, a warning is printed to stderr. Informational/progress messages go to stderr; only the per-string and per-function result lines (address, name, output path) go to stdout. Prints total elapsed time on completion.

- **`is_license_error(err: &IDAError) -> bool`**: Returns `true` for a Hex-Rays license error. Used by every place that must stop on license errors while ignoring other decompilation errors. Matching `&IDAError` relies on default binding modes, which is why `clippy::pattern_type_mismatch` is allowed in `Cargo.toml`.

- **`string_dirname(addr, string: &str) -> String`**: Returns the output subdirectory name `_{addr:X}_{sanitized_string}_`, via `filter_printable_chars()` and haruspex's `sanitize_filename()` (which also truncates the string to 64 chars). Since the string comes from the analyzed binary, the name must always be a single path component: `sanitize_filename()` replaces `/` and `.` on every platform, which prevents path traversal.

- **`create_parent_dir(filepath: &Path) -> io::Result<()>`**: Creates the parent directory of `filepath` and its missing ancestors (via `fs::create_dir_all`), if `filepath` has a parent. Used by `DumpedFunction`'s methods, which only take `output_path` and derive the string's subdirectory from it.

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
- XREFs outside any function are printed as `{from:#X} in [unknown]` on stdout and not counted as string uses.
- Functions that fail to decompile are reported on stdout, skipped (not counted as string uses), and not retried.
- If no string uses are found, the output directory is deleted and an error is returned.

### External dependencies

- **idalib** (0.10): Rust bindings for IDA's idalib (headless SDK).
- **haruspex** (0.10.1 or later): Decompiler helper; provides `dump_cfunc_pseudocode_to_file`, `dump_cfunc_types_to_file` (both added in 0.10.1), `sanitize_filename`, `output_path_for_function`, `prepare_output_dir`, `ArgHintsMode`, and `HaruspexError`.
- **anyhow** (1.0): Error handling.
- **idalib-build** (0.10): Build-time linkage configuration (used in `build.rs`).

## Lint policy

All clippy lint groups (`all`, `pedantic`, `nursery`, `cargo`, `restriction`) are enabled as warnings in `Cargo.toml` and treated as errors by `cargo clippy -- -D warnings`. A small set of restriction lints are explicitly allowed (e.g. `implicit_return`, `question_mark_used`, `print_stdout`, `pattern_type_mismatch`). Use `anyhow`/`?` for error propagation and `Option` combinators instead of `unwrap`/`expect`. When a restriction lint must be suppressed, use `#[expect(..., reason = "...")]` rather than `#[allow(...)]`.

## Tests

**Unit tests** (`src/lib.rs`, `#[cfg(test)]`): don't need an IDA database, and cover:

- `filter_printable_chars`
- `string_dirname`: name format, stripping of non-printable chars, and no path traversal (the result must be a single `Component::Normal`)
- `DumpedFunction::copy_to`: no-op when the files are already in place, copying `.c` and `.h` and repointing `source` (regression test for copying the same files twice), copying only the `.c` without a header, and creating a missing output directory. These use per-test temporary directories created by `test_dir()` under `env::temp_dir()`, scoped to a label and the process ID.

The tests module has `#[expect(clippy::panic_in_result_fn)]`, since the file-system tests return `io::Result<()>`.

**Integration tests** (`tests/main.rs`): custom harness (`harness = false`) whose `main()` calls one `test_*()` function per scenario, which runs augur and then calls one `check_*()` function per assertion; each check prints its own `[*] Checking ...` progress line. `reset_output()` removes any stale IDB file and output directory before each run, and the expected counts are module-level constants. `test_binary_with_string_uses()` runs against `tests/data/dox_sig_parser` and asserts:

- Exactly 18 decompiled string uses (only 5 without the `recover_strings()` pre-pass)
- Exactly 10 output subdirectories
- A specific total file count in the output tree (subdirectories + `.c` files + `.h` files + the root; several uses in the same function share one `.c` file)
- `_4020A8_Parsing type error at line %d__/` exists and is non-empty (regression test for `recover_strings()`: this string's uses are only found after decompiling all functions upfront)
- `_402108__atoi_/sub_401B00@401B00.c` does not contain Hex-Rays argument name hints (regression test for the hints-disabled default)
- `_4020C8_type ERROR_/sub_400C80@400C80.c` exists and is non-empty (spot-checks naming and decompilation output)
- `_4020C8_type ERROR_/sub_401750@401750.h` does not exist (regression test for the `TypesEmpty` case: no header when there are no type defs)
- `_4020C8_type ERROR_/sub_400C80@400C80.h` exists and is non-empty (regression test for the normal case: header written alongside the `.c` file)
- `sub_400C80@400C80.c` and `.h`, which reference several strings, appear in exactly 8 string subdirectories with byte-identical content (end-to-end regression test for reusing output files instead of decompiling again)
- No IDB file (`.i64`, or unpacked `.id0`/`.id1`/`.id2`/`.nam`/`.til`) is left next to the binary

`test_binary_without_string_uses()` then runs against `tests/data/no_strings`, a minimal macOS arm64 Mach-O binary built from `tests/data/no_strings.c` (`cc -O0 -o no_strings no_strings.c`), and asserts:

- `run()` returns the "No string uses were found" error
- The output directory `no_strings.str/` does not exist afterwards (regression test for the single cleanup point in `run()`)

`test_existing_output_dir()` creates a non-empty `no_strings.str/` before running against `tests/data/no_strings`, and asserts:

- `run()` returns the "already exists" error from `prepare_output_dir()`
- The existing file is still there and unchanged (regression test that the cleanup point never deletes pre-existing user data, which relies on `prepare_output_dir()` staying before `extract_string_uses()`)

`test_missing_binary()` runs against the nonexistent `tests/data/missing`, and asserts:

- `run()` returns the "Failed to analyze binary file" error
- No output directory is created (`IDB::open()` fails before `prepare_output_dir()`)

All scenarios run sequentially in the same process, each with its own `IDB::open()`. The harness stops at the first failed check. Test harness progress messages are printed to stderr.

Uses the `walkdir` dev-dependency. Requires a live IDA installation.
