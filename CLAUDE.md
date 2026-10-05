# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Augur** is an IDA headless plugin (written in Rust) that extracts strings and related pseudocode from binaries. It uses idalib's headless SDK to auto-analyze a binary, finds all string XREFs, decompiles the referencing functions, and writes the pseudocode to a `<binary>.str/` output directory organized by string.

## Build requirements

- IDA 9.4+ (see the README's compatibility table) with the Hex-Rays decompiler and a valid license, with `IDADIR` set to the installation directory at both build time and runtime. The build script (`build.rs`, via `idalib-build`) checks common installation paths if it's unset, and only warns if it can't find IDA, so set it explicitly for non-standard locations (`export IDADIR=/path/to/ida`).
- LLVM/Clang, used by bindgen when building `idalib`. On Windows, `LIBCLANG_PATH` must also be set to the LLVM/Clang `bin` directory.
- Rust edition 2024.

## Commands

```bash
# Build
cargo build --release --locked     # optimized (LTO, stripped, O3)
cargo build --locked               # debug build (no debug info, for faster startup)

# Unit tests (no IDA database needed)
cargo test --lib --locked

# Integration tests (custom harness, needs a working IDA installation)
cargo test --test tests --locked

# Lint and format (CI enforces these as errors)
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings

# Documentation (CI enforces this as an error)
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

# Dependency vulnerability audit (requires cargo-audit)
cargo audit

# Semver compatibility (requires cargo-semver-checks)
cargo semver-checks
```

`--workspace` follows the `rust-style` skill; this is a single crate, so it is equivalent to CI's `cargo clippy --all-targets --locked -- -D warnings`. `--no-deps` matches CI's `build.yml` doc step and skips documenting dependencies (`doc.yml`, which publishes to `gh-pages`, runs a plain `cargo doc --locked`).

CI's own `test` step only runs `cargo test --no-run` — a compile-only smoke check. Both test suites link against the IDA libraries, and the integration suite also needs a working IDA installation to analyze binaries, which CI runners don't have, so both only run locally.

## Architecture

This is a **single-crate project** — no workspace, just `src/main.rs` (CLI entry point) and `src/lib.rs` (all core logic).

### Key types and functions

- **`DumpCache`**: Type alias for `HashMap<Address, Option<haruspex::DumpedFunction>>`, keyed by function start address and shared across all strings (it's the `dumped` field of `FunctionDumper`). `None` records a function that failed to decompile, so it is not retried. haruspex's `DumpedFunction` records the `.c` path (`pseudocode`) and the sibling `.h` path (`types`, `None` when there were no type definitions to dump); augur no longer has a struct of its own.

- **`StringUses`**: Private counts struct (`dumped`, `skipped`, `outside_functions`) filled by `FunctionDumper`: uses in functions whose pseudocode was dumped, uses in functions that can't be decompiled (the `[decompilation failed]` lines), and references outside any function (the `[unknown]` lines); references from thunks aren't counted. Each `traverse_xrefs()` call returns the counts for one string, and `dump_all()` adds them up with `StringUses::merge` (saturating adds). `run()` prints all three in the summary, `[+] Found N string uses in functions (M skipped, K unknown), decompiled into ...`, and returns only `dumped`.

- **`FunctionDumper<'a>`**: Context struct that holds the borrowed IDB (`idb: &'a IDB`) and the `DumpCache` derived from it (`dumped`), so that its methods don't thread them through every call (same pattern as rhabdomancer's `CallMarker`). Built with `FunctionDumper::new(idb)` in `extract_string_uses()`, after `recover_strings()`, which needs `&mut IDB` and therefore stays a free function, and used as `FunctionDumper::new(idb).dump_all(dirpath)` (same pattern as rhabdomancer's `CallMarker::new(&idb).mark_all(&found)`). Has three methods:
  - `dump_all(dirpath) -> Result<StringUses, HaruspexError>`: Iterates `self.idb.strings().iter()` (which skips invalid entries in the string list), and for each string builds its subdirectory path via `string_dirname()` and dispatches `traverse_xrefs()` (the subdirectory is only created if something is written in it), and adds up the `StringUses` each call returns with `merge`. Any of the counts may be zero.
  - `traverse_xrefs(addr, dirpath) -> Result<StringUses, HaruspexError>`: Iteratively walks the XREF chain to the string at `addr` with `iter::successors(idb.first_xref_to(addr, XRefQuery::ALL), XRef::next_to)`; for each non-thunk function, calls `dump_function_pseudocode()` into the string's subdirectory `dirpath`, and returns the string's counts: each XREF is counted as `dumped` or `skipped`, depending on its result, or as `outside_functions` for an XREF outside any function, with saturating adds. A function that fails to decompile is skipped without affecting the string's other XREFs.
  - `dump_function_pseudocode(func, from, dirpath) -> Result<bool, HaruspexError>`: Gets the function's name once with `haruspex::function_name`, builds the output path with `haruspex::output_path_for_function(&func_name, addr, dirpath)`, makes the function's output files available in `dirpath`, and prints the result (`` + `f@ADDR.h` `` is appended only when there is a `.h`), with the name escaped by `str::escape_debug()` since it comes from the binary (the same technique as haruspex; strings are already printed with `{:?}`). Each function is decompiled at most once per run, tracked by `dumped`: on first use, the entry is filled with `haruspex::decompile_to_file()`, which returns `Ok(None)` for a function that can't be decompiled and creates the string's subdirectory only once there is something to write, so no empty directories are left behind; then `DumpedFunction::copy_to()` is called unconditionally on the cached entry, which copies the files only if they were dumped for another string and then points the entry at the copies. Returns `true` if the pseudocode was dumped; returns `false` and prints `{from:#X} in {func_name} -> [decompilation failed]` if the function can't be decompiled. Since all uses of one string are handled in a single `traverse_xrefs()` call, repeated uses within a string never copy the files twice. This matters because idalib decompiles with `DECOMP_NO_CACHE`, so every decompilation is a full one.

- **`recover_strings(idb: &mut IDB) -> Result<(), HaruspexError>`**: Free function that decompiles every non-thunk function upfront with `haruspex::decompile`, discarding the output, to let IDA 9.4's decompiler recover additional strings. Then calls `idb.auto_wait()` (printing a warning if it returns `false`) followed by `idb.strings().rebuild()`. The decompiler only queues the new string items for auto-analysis, so without `auto_wait()` the rebuilt string list would not include them; keep these three steps together and in this order. Ignores `HaruspexError::Decompile` (one function can't be decompiled) and returns early with any other error (e.g., `LicenseUnavailable`), so it follows haruspex's own rules on which failures are fatal. The functions referencing strings are decompiled again later, on purpose: a pre-pass decompilation can predate the strings it uses.

- **`extract_string_uses(idb: &mut IDB, dirpath) -> Result<usize, HaruspexError>`**: Free function holding all the work that writes into the output directory. Calls `recover_strings()`, then builds a `FunctionDumper` and returns the count from `FunctionDumper::dump_all()`. Returns a concrete error type, like every function below `run()`, and may return a count of zero: rejecting zero uses is `run()`'s job.

- **`run(filepath: impl AsRef<Path>) -> anyhow::Result<usize>`**: Public entry point. Converts `filepath` once with `as_ref()`, then opens the binary via `IDB::open()`, disables the Hex-Rays argument name hints with `ArgHintsMode::Disabled.apply(&mut idb)` (which also checks that a decompiler is available, and comes before any decompilation, so that every decompilation, including the `recover_strings()` pre-pass, picks up the config change), calls `haruspex::prepare_output_dir()` to set up the `<binary>.str/` directory (printing the `[*] Preparing output directory` and `[+] Output directory is ready` lines itself, since `prepare_output_dir` prints nothing), then calls `extract_string_uses()` and returns the number of dumped uses. The output directory is named after the binary with its extension, if any, replaced by `.str`, so `foo.exe` and `foo` both produce `foo.str`. `prepare_output_dir()` must stay before `extract_string_uses()` and outside the cleanup: this makes an existing non-empty directory fail fast, before the slow pre-pass, and ensures the cleanup never deletes a pre-existing directory with the user's previous results. Only `run()` converts errors to `anyhow`: it maps the `HaruspexError` from `extract_string_uses()` into an `anyhow::Error`, then rejects zero dumped uses with `anyhow::ensure!`, both inside the cleanup. This is the single cleanup point: if either step fails (including no string uses found), the output directory is removed and the original error is returned; if removing the directory fails too, a warning is printed to stderr. Prints total elapsed time on completion.

- **`string_dirname(addr, string: &str) -> String`**: Returns the output subdirectory name `_{addr:X}_{sanitized_string}_`, via `filter_printable_chars()` and haruspex's `sanitize_filename()` (which also truncates the string to 64 bytes on a char boundary, and replaces control chars). Since the string comes from the analyzed binary, the name must always be a single path component: `sanitize_filename()` replaces `/` and `.` on every platform, which prevents path traversal.

- **`filter_printable_chars(string: &str) -> String`**: Returns only ASCII graphic characters and spaces — used to produce a human-readable string before passing to `sanitize_filename()`.

### External dependencies

- **idalib** (0.10): Rust bindings for IDA's idalib (headless SDK).
- **haruspex** (1.0, used from the local `../haruspex` checkout through `[patch.crates-io]` in `Cargo.toml` until it's published): Decompiler helper; provides `decompile`, `decompile_to_file`, `DumpedFunction` (and its `copy_to`), `function_name`, `output_path_for_function`, `sanitize_filename`, `prepare_output_dir`, `ArgHintsMode`, and `HaruspexError`.
- **anyhow** (1.0): Error handling.
- **idalib-build** (0.10): Build-time linkage configuration (used in `build.rs`).

## Output

Results go to stdout (`println!`); everything else (banner, progress, summary, timing, errors) goes to stderr (`eprintln!`), with the prefixes `[*]` for progress, `[+]` for success and summaries, `[-]` for information, and `[!]` for warnings and errors, and the elapsed time as `{:.1} seconds`. Preserve this split when adding new output. The results are the per-string header lines and the per-use result lines (address, name, output path).

Output layout:

```
<binary>.str/
  _{addr:X}_{sanitized_string}_/
    {func_name}@{addr}.c
    {func_name}@{addr}.h   # only when the function has type definitions to dump
    ...
```

## Error handling

- Functions below `run()` return `HaruspexError`; only `run()` uses `anyhow::Result<T>`.
- Any error after the output directory is created (including Hex-Rays license errors and I/O errors) removes the output directory and exits with that error. `run()` is the only place that performs this cleanup.
- Thunk functions are silently skipped.
- XREFs outside any function are printed as `{from:#X} in [unknown]` on stdout and not counted as string uses.
- Functions that fail to decompile are reported on stdout, skipped (not counted as string uses), and not retried.
- If no string uses are found, the output directory is deleted and an error is returned.
- `main()` prints errors as `[!] Error: {err:#}` (the full context chain) and exits with `ExitCode::FAILURE`.

## Lint policy

All clippy lint groups (`all`, `pedantic`, `nursery`, `cargo`, `restriction`) are enabled as warnings in the workspace lints of `Cargo.toml` (the same configuration in augur, haruspex, and rhabdomancer) and treated as errors by `cargo clippy -- -D warnings`. A curated set of restriction lints is explicitly allowed (e.g., `implicit_return`, `question_mark_used`, `print_stdout`, `pattern_type_mismatch`), and `linker_messages = "allow"` is a temporary workaround for <https://github.com/idalib-rs/idalib/issues/81>. Notably forbidden outside tests:

- `unwrap`, `expect`, `panic`, `todo`, `unimplemented`, `unreachable`, `dbg_macro`: use `?`, `anyhow` context, and `Option` combinators instead.
- Unsafe blocks without a `// Safety:` comment (`undocumented_unsafe_blocks`).
- Undocumented items (`missing_docs`, `missing_docs_in_private_items`): every item has a doc comment, private ones and test helpers included.

`clippy::min_ident_chars` is enabled, so single-character identifiers (e.g. `|s|`, `for f in`) are flagged — use descriptive names like `name`, `func`, `idx`. Clippy's default `allowed-idents-below-min-chars` still permits `i`, `j`, `x`, `y`, `z`, `w`, and `n`, and parameters that keep a trait's own name (such as `f` in `fmt::Display::fmt`) are not flagged either; prefer descriptive names (e.g. `idx`) anyway.

Pure functions whose result matters carry `#[must_use]`, private ones included (clippy's `must_use_candidate` only flags public items), e.g., `FunctionDumper::new()`, `string_dirname()`, and `filter_printable_chars()`.

Use `#[expect(clippy::some_lint, reason = "...")]`, never `#[allow]`, to locally suppress a lint that genuinely cannot be avoided, in both library code and tests. The only one in the codebase: `panic_in_result_fn` (test assertions, as a module-level `#![expect]` in `tests/main.rs`).

Taplo enforces TOML formatting (`.taplo.toml`: 120-char line width, 4-space indent).

The crate-level documentation in `src/lib.rs` is assembled in a specific order to satisfy two restriction lints simultaneously, and should not be "simplified" back to a plain `#![doc = include_str!("../README.md")]`:

- `#![doc = env!("CARGO_PKG_DESCRIPTION")]` is always present (pulls the `description` from `Cargo.toml` with no duplication) so the crate is documented in every build configuration — this satisfies `missing_docs`, which runs without `--cfg doc`.
- `#![cfg_attr(doc, doc = include_str!("../README.md"))]` pulls in the README only under `cfg(doc)`, satisfying `clippy::doc_include_without_cfg`.
- The `#![doc = ""]` between them forces a Markdown paragraph break so the description and the README's leading heading don't merge.

## Tests

### Unit tests

`#[cfg(test)] mod tests` at the end of `src/lib.rs` doesn't need an IDA database, and covers:

- `filter_printable_chars`
- `string_dirname`: name format, stripping of non-printable chars, and no path traversal (the result must be a single `Component::Normal`)

The tests for reusing a function's output files (`DumpedFunction::copy_to`) moved to haruspex together with the method.

### Integration tests

`tests/main.rs` holds the integration tests, with a custom harness (`harness = false`) whose `main()` first calls `idalib::force_batch_mode()`, like the binary, then calls one `test_*()` function per scenario, which runs augur and then calls one `check_*()` function per assertion; each check prints its own `[*] Checking ...` progress line. `reset_output()` removes any stale IDB files (every extension in `IDB_EXTENSIONS`, shared with `check_no_idb_file()`) and output directory before each run, and again at the end of the scenarios that produce output, and the expected counts are module-level constants. Expected errors are matched against the full error chain (`format!("{err:#}")`), i.e., what users see. These conventions match rhabdomancer's harness. `test_binary_with_string_uses()` runs the real binary through `run_binary()` against `tests/data/dox_sig_parser`, pinning the CLI output with literals in the same analysis, and asserts:

- The binary exits successfully
- stdout has exactly 39 blank lines and 39 string header lines (one per string, `N_STRINGS`), 18 string use lines (`N_USES`, only 5 without the `recover_strings()` pre-pass), 28 `[unknown]` lines (`N_UNKNOWN`), and nothing else
- stdout contains the literal use line ``0x400C98 in sub_400C80 -> `./tests/data/dox_sig_parser.str/_401FF8__db_etc_ip-reputation_DoH_SERVER_LIST_/sub_400C80@400C80.c` + `sub_400C80@400C80.h` `` and the literal `0x400088 in [unknown]`
- stderr contains the literal summary ``[+] Found 18 string uses in functions (0 skipped, 28 unknown), decompiled into `./tests/data/dox_sig_parser.str` ``
- Exactly 10 output subdirectories
- A specific total file count in the output tree (subdirectories + `.c` files + `.h` files + the root; several uses in the same function share one `.c` file)
- `_4020A8_Parsing type error at line %d__/` exists and is non-empty (regression test for `recover_strings()`: this string's uses are only found after decompiling all functions upfront)
- `_402108__atoi_/sub_401B00@401B00.c` does not contain Hex-Rays argument name hints (regression test for the hints-disabled default)
- `_4020C8_type ERROR_/sub_400C80@400C80.c` exists and is non-empty (spot-checks naming and decompilation output)
- `_4020C8_type ERROR_/sub_401750@401750.h` does not exist (regression test for the `TypesEmpty` case: no header when there are no type defs)
- `_4020C8_type ERROR_/sub_400C80@400C80.h` exists and is non-empty (regression test for the normal case: header written alongside the `.c` file)
- `sub_400C80@400C80.c` and `.h`, which reference several strings, appear in exactly 8 string subdirectories with byte-identical content (end-to-end regression test for reusing output files instead of decompiling again)
- No IDB file (`.i64`, or unpacked `.id0`/`.id1`/`.id2`/`.nam`/`.til`) is left next to the binary

`test_binary_with_skipped_uses()` runs the real binary against `tests/data/too_big`, an x86-64 ELF object file built from `tests/data/too_big.c` (`clang -target x86_64-linux-gnu -O0 -c -o too_big too_big.c`): its `too_big` function is about twice Hex-Rays' `MAX_FUNCSIZE` limit (64 KB, in `hexrays.cfg`), made of macro-expanded stores to a `volatile` local (which need no relocation, keeping the fixture small), so it can't be decompiled, while `small` can; each references its own string. Neither `dox_sig_parser` nor haruspex's `ls` has a string use in a function that fails to decompile (their undecompilable functions are imports, which reference no strings), which is why this fixture exists. It asserts:

- The binary exits successfully
- stdout contains the literal `0x8 in too_big -> [decompilation failed]`
- stderr contains the literal summary ``[+] Found 1 string uses in functions (1 skipped, 0 unknown), decompiled into `./tests/data/too_big.str` ``
- No subdirectory is created for the string used only by `too_big` (`haruspex::decompile_to_file` creates directories only after a successful decompilation), while `small@22300.c` is written for the other string
- No IDB file is left next to the binary

`test_binary_without_string_uses()` then runs against `tests/data/no_strings`, a minimal macOS arm64 Mach-O binary built from `tests/data/no_strings.c` (`cc -O0 -o no_strings no_strings.c`), and asserts:

- `run()` returns the "no string uses were found" error
- The output directory `no_strings.str/` does not exist afterwards (regression test for the single cleanup point in `run()`)
- No IDB file is left next to the binary

`test_existing_output_dir()` creates a non-empty `dox_sig_parser.str/` before running against `tests/data/dox_sig_parser`, then empties it and runs again (the same shape as haruspex's scenario), and asserts:

- `run()` returns the "already exists" error from `prepare_output_dir()`
- The existing file is still there and unchanged (regression test that the cleanup point never deletes pre-existing user data, which relies on `prepare_output_dir()` staying before `extract_string_uses()`)
- With the directory empty, `run()` succeeds and returns 18, the number of dumped uses; this is the only check of `run()`'s return value on success, and `dox_sig_parser`'s dumped, skipped, and unknown counts all differ (18, 0, 28), so returning the wrong one would be caught
- No IDB file is left next to the binary

`test_missing_binary()` runs against the nonexistent `tests/data/missing`, and asserts:

- `run()` returns the "failed to analyze binary file" error
- No output directory is created (`IDB::open()` fails before `prepare_output_dir()`)

`test_invalid_arguments()` runs the real binary (via `run_binary()`, with `env!("CARGO_BIN_EXE_augur")`) with no arguments, two arguments (`tests/data/no_strings` twice), `-h`, and `--help`, and asserts:

- Each run fails, prints `Usage:` to stderr, and prints nothing to stdout (checked by `check_usage()`)
- No IDB file and no output directory are created for `tests/data/no_strings`

It covers the only branching in `src/main.rs`; IDA never opens a database here, so it's fast.

Each scenario uses its own `IDB::open()`.

Uses the `walkdir` dev-dependency. Requires a live IDA installation.

Conventions shared by the augur, haruspex, and rhabdomancer harnesses:

- All scenarios run sequentially in the same process; the harness stops at the first failed check, and its progress messages go to stderr.
- Expected values that pin an external contract (CLI output lines, summaries, file names, annotation tags, error substrings) are literals, never production constants, so that an accidental change fails the tests.
- Expected errors are matched against the full error chain (`format!("{err:#}")`), i.e., what users see; OS-dependent failures are checked by downcasting to `io::ErrorKind`, not by message.
- Only the module-level `#![expect(clippy::panic_in_result_fn)]` is needed: fallible lookups use `.context(...)?` instead of `expect`, and conversions use `try_from` instead of `as`.
- New checks must be shown to fail: temporarily break the behavior they guard, run the suite, restore. If an earlier check catches the break first, break it differently, so that the new check is shown to fail on its own.

## IDA integration notes

- `idalib::force_batch_mode()` must be called before opening any database (suppresses IDA UI); `main()` and the test harness both call it first.
- IDA must run on the main thread and isn't thread-safe, so standard `#[test]` functions, which run on worker threads, can't use it: that's why the integration tests use a custom harness (`harness = false`).
- Objects derived from an `IDB` (e.g., `Function`, `CFunction`) must be dropped before the `IDB` itself, since their destructors call into IDA: idalib's lifetimes don't enforce this at implicit scope-end drops, and getting it wrong hangs the process.
- Names from the analyzed binary (function names, strings) are untrusted: print them escaped with `str::escape_debug()` (or `{:?}`) at the print site, and build file names from them only through a sanitizer.
- To probe IDA's view of a binary, write a temporary `examples/` program (`cargo run --example ...`), then delete it.
- `IDB::open()` doesn't save the database on close, so no IDB file is left next to the binary (checked by `check_no_idb_file()`).
- idalib decompiles with `DECOMP_NO_CACHE`, so every decompilation is a full one: each function referencing strings is decompiled at most once per run (`DumpCache`), besides the `recover_strings()` pre-pass.
- Decompiling only queues the strings it recovers for auto-analysis, so `recover_strings()` calls `auto_wait()` before rebuilding the string list.
- Thunk functions (`FunctionFlags::THUNK`) are skipped.

## CI workflows

- **`build.yml`** — lint/build/test matrix across Linux, macOS, and Windows, plus a `zizmor` job that audits `.github/workflows/*.yml` for security issues (credential handling, injection, etc.).
- **`doc.yml`** — builds rustdoc and pushes it to the `gh-pages` branch on `v*` tags; its `checkout` step needs persisted git credentials to `git push` later, so it carries a `# zizmor: ignore[artipacked]` suppression comment.
- To suppress a specific zizmor finding, add an inline `# zizmor: ignore[<rule-id>]` comment on the flagged step with a short justification, rather than disabling the rule globally.
