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

- **`DumpCache`**: Type alias for `HashMap<Address, Option<haruspex::DumpedFunction>>`, keyed by function start address and shared across all strings (it's the `dumped` field of `FunctionDumper`). `None` records a function that failed to decompile, so it is not retried. haruspex's `DumpedFunction` records the `.c` path (`pseudocode`) and the sibling `.h` path (`types`, `None` when there were no type definitions to dump); augur no longer has a struct of its own.

- **`FunctionDumper<'a>`**: Context struct that holds the borrowed IDB (`idb: &'a IDB`) and the `DumpCache` derived from it (`dumped`), so that its methods don't thread them through every call (same pattern as rhabdomancer's `CallMarker`). Built with `FunctionDumper::new(idb)` in `extract_string_uses()`, after `recover_strings()`, which needs `&mut IDB` and therefore stays a free function, and used as `FunctionDumper::new(idb).dump_all(dirpath)` (same pattern as rhabdomancer's `CallMarker::new(&idb).mark_all(&found)`). Has three methods:
  - `dump_all(dirpath) -> Result<usize, HaruspexError>`: Iterates `self.idb.strings().iter()` (which skips invalid entries in the string list), and for each string builds its subdirectory path via `string_dirname()` and dispatches `traverse_xrefs()` (the subdirectory is only created if something is written in it), summing the returned counts with `saturating_add`. May return a count of zero.
  - `traverse_xrefs(addr, dirpath) -> Result<usize, HaruspexError>`: Iteratively walks the XREF chain to the string at `addr` with `iter::successors(idb.first_xref_to(addr, XRefQuery::ALL), XRef::next_to)`; for each non-thunk function, calls `dump_function_pseudocode()` into the string's subdirectory `dirpath`, and returns the number of calls that returned `true`. A function that fails to decompile is skipped without affecting the string's other XREFs.
  - `dump_function_pseudocode(func, from, dirpath) -> Result<bool, HaruspexError>`: Gets the function's name once with `haruspex::function_name`, builds the output path with `haruspex::output_path_for_function(&func_name, addr, dirpath)`, makes the function's output files available in `dirpath`, and prints the result (`` + `f@ADDR.h` `` is appended only when there is a `.h`). Each function is decompiled at most once per run, tracked by `dumped`: on first use, the entry is filled with `haruspex::decompile_to_file()`, which returns `Ok(None)` for a function that can't be decompiled and creates the string's subdirectory only once there is something to write, so no empty directories are left behind; then `DumpedFunction::copy_to()` is called unconditionally on the cached entry, which copies the files only if they were dumped for another string and then points the entry at the copies. Returns `true` if the pseudocode was dumped; returns `false` and prints `{from:#X} in {func_name} -> [decompilation failed]` if the function can't be decompiled. Since all uses of one string are handled in a single `traverse_xrefs()` call, repeated uses within a string never copy the files twice. This matters because idalib decompiles with `DECOMP_NO_CACHE`, so every decompilation is a full one.

- **`recover_strings(idb: &mut IDB) -> Result<(), HaruspexError>`**: Free function that decompiles every non-thunk function upfront with `haruspex::decompile`, discarding the output, to let IDA 9.4's decompiler recover additional strings. Then calls `idb.auto_wait()` (printing a warning if it returns `false`) followed by `idb.strings().rebuild()`. The decompiler only queues the new string items for auto-analysis, so without `auto_wait()` the rebuilt string list would not include them; keep these three steps together and in this order. Ignores `HaruspexError::Decompile` (one function can't be decompiled) and returns early with any other error (e.g., `LicenseUnavailable`), so it follows haruspex's own rules on which failures are fatal. The functions referencing strings are decompiled again later, on purpose: a pre-pass decompilation can predate the strings it uses.

- **`extract_string_uses(idb: &mut IDB, dirpath) -> Result<usize, HaruspexError>`**: Free function holding all the work that writes into the output directory. Calls `recover_strings()`, then builds a `FunctionDumper` and returns the count from `FunctionDumper::dump_all()`. Returns a concrete error type, like every function below `run()`, and may return a count of zero: rejecting zero uses is `run()`'s job.

- **`run(filepath: impl AsRef<Path>) -> anyhow::Result<usize>`**: Public entry point. Converts `filepath` once with `as_ref()`, then opens the binary via `IDB::open()`, disables the Hex-Rays argument name hints with `ArgHintsMode::Disabled.apply(&mut idb)` (which also checks that a decompiler is available, and comes before any decompilation, so that every decompilation, including the `recover_strings()` pre-pass, picks up the config change), calls `haruspex::prepare_output_dir()` to set up the `<binary>.str/` directory (printing the `[*] Preparing output directory` and `[+] Output directory is ready` lines itself, since `prepare_output_dir` prints nothing), then calls `extract_string_uses()` and returns its total use count. The output directory is named after the binary with its extension, if any, replaced by `.str`, so `foo.exe` and `foo` both produce `foo.str`. `prepare_output_dir()` must stay before `extract_string_uses()` and outside the cleanup: this makes an existing non-empty directory fail fast, before the slow pre-pass, and ensures the cleanup never deletes a pre-existing directory with the user's previous results. Only `run()` converts errors to `anyhow`: it maps the `HaruspexError` from `extract_string_uses()` into an `anyhow::Error`, then rejects a count of zero with `anyhow::ensure!`, both inside the cleanup. This is the single cleanup point: if either step fails (including no string uses found), the output directory is removed and the original error is returned; if removing the directory fails too, a warning is printed to stderr. Informational/progress messages go to stderr; only the per-string and per-function result lines (address, name, output path) go to stdout. Prints total elapsed time on completion.

- **`string_dirname(addr, string: &str) -> String`**: Returns the output subdirectory name `_{addr:X}_{sanitized_string}_`, via `filter_printable_chars()` and haruspex's `sanitize_filename()` (which also truncates the string to 64 bytes on a char boundary, and replaces control chars). Since the string comes from the analyzed binary, the name must always be a single path component: `sanitize_filename()` replaces `/` and `.` on every platform, which prevents path traversal.

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

- Functions below `run()` return `HaruspexError`; only `run()` uses `anyhow::Result<T>`.
- Any error after the output directory is created (including Hex-Rays license errors and I/O errors) removes the output directory and exits with that error. `run()` is the only place that performs this cleanup.
- Thunk functions are silently skipped.
- XREFs outside any function are printed as `{from:#X} in [unknown]` on stdout and not counted as string uses.
- Functions that fail to decompile are reported on stdout, skipped (not counted as string uses), and not retried.
- If no string uses are found, the output directory is deleted and an error is returned.

### External dependencies

- **idalib** (0.10): Rust bindings for IDA's idalib (headless SDK).
- **haruspex** (1.0, used from the local `../haruspex` checkout through `[patch.crates-io]` in `Cargo.toml` until it's published): Decompiler helper; provides `decompile`, `decompile_to_file`, `DumpedFunction` (and its `copy_to`), `function_name`, `output_path_for_function`, `sanitize_filename`, `prepare_output_dir`, `ArgHintsMode`, and `HaruspexError`.
- **anyhow** (1.0): Error handling.
- **idalib-build** (0.10): Build-time linkage configuration (used in `build.rs`).

## Lint policy

All clippy lint groups (`all`, `pedantic`, `nursery`, `cargo`, `restriction`) are enabled as warnings in `Cargo.toml` and treated as errors by `cargo clippy -- -D warnings`. A small set of restriction lints are explicitly allowed (e.g. `implicit_return`, `question_mark_used`, `print_stdout`, `pattern_type_mismatch`). Use `anyhow`/`?` for error propagation and `Option` combinators instead of `unwrap`/`expect`. When a restriction lint must be suppressed, use `#[expect(..., reason = "...")]` rather than `#[allow(...)]`.

## Tests

**Unit tests** (`src/lib.rs`, `#[cfg(test)]`): don't need an IDA database, and cover:

- `filter_printable_chars`
- `string_dirname`: name format, stripping of non-printable chars, and no path traversal (the result must be a single `Component::Normal`)

The tests for reusing a function's output files (`DumpedFunction::copy_to`) moved to haruspex together with the method.

**Integration tests** (`tests/main.rs`): custom harness (`harness = false`) whose `main()` first calls `idalib::force_batch_mode()`, like the binary, then calls one `test_*()` function per scenario, which runs augur and then calls one `check_*()` function per assertion; each check prints its own `[*] Checking ...` progress line. `reset_output()` removes any stale IDB files (every extension in `IDB_EXTENSIONS`, shared with `check_no_idb_file()`) and output directory before each run, and again at the end of the scenarios that produce output, and the expected counts are module-level constants. Expected errors are matched against the full error chain (`format!("{err:#}")`), i.e., what users see. These conventions match rhabdomancer's harness. `test_binary_with_string_uses()` runs against `tests/data/dox_sig_parser` and asserts:

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

- `run()` returns the "no string uses were found" error
- The output directory `no_strings.str/` does not exist afterwards (regression test for the single cleanup point in `run()`)
- No IDB file is left next to the binary

`test_existing_output_dir()` creates a non-empty `no_strings.str/` before running against `tests/data/no_strings`, and asserts:

- `run()` returns the "already exists" error from `prepare_output_dir()`
- The existing file is still there and unchanged (regression test that the cleanup point never deletes pre-existing user data, which relies on `prepare_output_dir()` staying before `extract_string_uses()`)
- No IDB file is left next to the binary

`test_missing_binary()` runs against the nonexistent `tests/data/missing`, and asserts:

- `run()` returns the "failed to analyze binary file" error
- No output directory is created (`IDB::open()` fails before `prepare_output_dir()`)

`test_invalid_arguments()` runs the real binary (via `run_binary()`, with `env!("CARGO_BIN_EXE_augur")`) with no arguments, two arguments (`tests/data/no_strings` twice), `-h`, and `--help`, and asserts:

- Each run fails, prints `Usage:` to stderr, and prints nothing to stdout (checked by `check_usage()`)
- No IDB file and no output directory are created for `tests/data/no_strings`

It covers the only branching in `src/main.rs`; IDA never opens a database here, so it's fast.

All scenarios run sequentially in the same process, each with its own `IDB::open()`. The harness stops at the first failed check. Test harness progress messages are printed to stderr.

Uses the `walkdir` dev-dependency. Requires a live IDA installation.
