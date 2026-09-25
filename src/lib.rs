#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/augur/master/.img/logo.png")]

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{fs, io, iter};

use anyhow::Context as _;
use haruspex::{
    ArgHintsMode, HaruspexError, dump_cfunc_pseudocode_to_file, dump_cfunc_types_to_file,
    output_path_for_function, prepare_output_dir, sanitize_filename,
};
use idalib::decompiler::HexRaysErrorCode;
use idalib::func::{Function, FunctionFlags};
use idalib::idb::IDB;
use idalib::xref::{XRef, XRefQuery};
use idalib::{Address, IDAError};

/// Output files of each function decompiled so far, keyed by function start address.
///
/// `None` means that the function failed to decompile, so it isn't retried.
type DumpCache = HashMap<Address, Option<DumpedFunction>>;

/// Output files already written for a decompiled function, used to avoid decompiling it again.
///
/// Created by [`DumpedFunction::decompile_to`] on first use, and reused via [`DumpedFunction::copy_to`]
/// for any further string use.
#[derive(Debug)]
struct DumpedFunction {
    /// Path of the most recently written `.c` pseudocode file.
    source: PathBuf,
    /// Whether a sibling `.h` file with type definitions was also written.
    has_header: bool,
}

impl DumpedFunction {
    /// Decompiles `func` and writes its output files at `output_path`, creating the parent directory of
    /// `output_path` only once there is something to write in it.
    ///
    /// Type definitions are best-effort: the `.h` file is only written if there are any, and a failure to
    /// dump them is ignored. Returns `None` if `func` cannot be decompiled.
    ///
    /// # Errors
    ///
    /// Returns [`HaruspexError`] if the output files cannot be created, or if the Hex-Rays decompiler license
    /// is not available for the target binary.
    fn decompile_to(
        idb: &IDB,
        func: &Function<'_>,
        output_path: &Path,
    ) -> Result<Option<Self>, HaruspexError> {
        let cfunc = match idb.decompile(func) {
            Ok(cfunc) => cfunc,

            // The Hex-Rays decompiler license is not available.
            Err(err) if is_license_error(&err) => return Err(err.into()),

            // The function can't be decompiled.
            Err(_) => return Ok(None),
        };

        // Only create the output directory once there is something to write in it.
        create_parent_dir(output_path)?;
        dump_cfunc_pseudocode_to_file(&cfunc, output_path)?;

        let has_header =
            match dump_cfunc_types_to_file(idb, &cfunc, output_path.with_extension("h")) {
                Ok(()) => true,

                // The Hex-Rays decompiler license is not available.
                Err(HaruspexError::DecompileFailed(err)) if is_license_error(&err) => {
                    return Err(err.into());
                }

                // Type definitions are best-effort: no header if there are none or dumping them failed.
                Err(HaruspexError::TypesEmpty | HaruspexError::DecompileFailed(_)) => false,

                // Propagate any other error.
                Err(err) => return Err(err),
            };

        Ok(Some(Self {
            source: output_path.to_owned(),
            has_header,
        }))
    }

    /// Makes the output files available at `output_path`, copying them from their previous location unless
    /// they are already in place, then tracks the copy so the files aren't copied again.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the output directory cannot be created or the output files cannot be copied.
    fn copy_to(&mut self, output_path: &Path) -> io::Result<()> {
        if self.source != output_path {
            create_parent_dir(output_path)?;
            fs::copy(&self.source, output_path)?;
            if self.has_header {
                fs::copy(
                    self.source.with_extension("h"),
                    output_path.with_extension("h"),
                )?;
            }
            output_path.clone_into(&mut self.source);
        }
        Ok(())
    }
}

/// Extracts strings and pseudocode/type definitions of each function that references them from the
/// binary at `filepath` and saves them in `filepath.str`.
///
/// Returns the number of string uses in functions whose pseudocode was dumped.
///
/// # Errors
///
/// Returns [`anyhow::Error`] if the binary file cannot be analyzed, if the decompiler or its license is not
/// available, if the output directory already exists and is not empty, if the output files cannot be created,
/// or if no string uses were found. On any error after the output directory is created, the directory is removed.
#[expect(
    clippy::shadow_reuse,
    reason = "shadowing is convenient and idiomatic here"
)]
pub fn run(filepath: impl AsRef<Path>) -> anyhow::Result<usize> {
    let start = Instant::now();
    let filepath = filepath.as_ref();

    eprintln!("[*] Analyzing binary file `{}`", filepath.display());
    let mut idb = IDB::open(filepath)
        .with_context(|| format!("Failed to analyze binary file `{}`", filepath.display()))?;
    eprintln!("[+] Successfully analyzed binary file");
    eprintln!();

    eprintln!("[-] Processor: {}", idb.processor().long_name());
    eprintln!("[-] Compiler: {:?}", idb.meta().cc_id());
    eprintln!("[-] File type: {:?}", idb.meta().filetype());
    eprintln!();

    anyhow::ensure!(idb.decompiler_available(), "Decompiler is not available");

    // Disable argument name hints.
    idb.modify_decompiler_config(ArgHintsMode::Disabled.directive())
        .context("Failed to set decompiler's argument hints mode")?;

    // Create a new output directory, returning an error if it already exists and it's not empty.
    let dirpath = filepath.with_extension("str");
    prepare_output_dir(&dirpath)?;

    // Remove the output directory, which is empty or only partially populated, if anything goes wrong.
    let string_uses_count = extract_string_uses(&mut idb, &dirpath).inspect_err(|_| {
        if let Err(cleanup_err) = fs::remove_dir_all(&dirpath) {
            eprintln!(
                "[!] Failed to remove directory `{}`: {cleanup_err}",
                dirpath.display()
            );
        }
    })?;

    eprintln!();
    eprintln!(
        "[+] Found {string_uses_count} string uses in functions, decompiled into `{}`",
        dirpath.display()
    );
    eprintln!(
        "[+] Done processing binary file `{}` in {:.1} seconds",
        filepath.display(),
        start.elapsed().as_secs_f64()
    );
    Ok(string_uses_count)
}

/// Recovers strings, then dumps pseudocode and type definitions of each function that references them
/// into `dirpath`, organized by string.
///
/// Returns the number of string uses in functions that were dumped.
///
/// # Errors
///
/// Returns [`anyhow::Error`] if the output files cannot be created, if the Hex-Rays decompiler license is not
/// available for the target binary, or if no string uses were found.
fn extract_string_uses(idb: &mut IDB, dirpath: &Path) -> anyhow::Result<usize> {
    // Leverage the full power of IDA to recover strings during decompilation.
    eprintln!();
    eprintln!("[*] Decompiling all functions and recovering strings...");
    recover_strings(idb)?;

    let mut string_uses_count: usize = 0;
    let mut dumped = DumpCache::new();

    eprintln!();
    eprintln!("[*] Finding cross-references to strings...");
    // Iterate over strings with their addresses, skipping any invalid entry in the string list.
    for (addr, string) in idb.strings().iter() {
        println!("\n{addr:#X} {string:?}");

        // Traverse XREFs to string and dump the related pseudocode and type definitions to the output files.
        let string_dirpath = dirpath.join(string_dirname(addr, &string));
        let count = traverse_xrefs(idb, addr, &string_dirpath, &mut dumped)?;
        string_uses_count = string_uses_count.saturating_add(count);
    }

    anyhow::ensure!(
        string_uses_count > 0,
        "No string uses were found, check your input file"
    );
    Ok(string_uses_count)
}

/// Decompiles all functions in the IDB to let IDA recover additional strings, ignoring decompilation
/// errors, then rebuilds the string list.
///
/// # Errors
///
/// Returns an [`IDAError`] if the Hex-Rays decompiler license is not available for the target binary.
fn recover_strings(idb: &mut IDB) -> Result<(), IDAError> {
    for (_id, func) in idb.functions() {
        // Skip the function if it has the `thunk` attribute.
        if func.flags().contains(FunctionFlags::THUNK) {
            continue;
        }

        // Bail out early if the Hex-Rays decompiler license is not available, ignore other IDA errors.
        if let Err(err) = idb.decompile(&func)
            && is_license_error(&err)
        {
            return Err(err);
        }
    }

    // The decompiler queues new string items for auto-analysis, so wait for it before rebuilding.
    if !idb.auto_wait() {
        eprintln!("[!] Auto-analysis failed");
    }
    idb.strings().rebuild();

    Ok(())
}

/// Iteratively traverses the XREFs to the string at `addr`, and dumps pseudocode and type definitions of each
/// referencing function into `dirpath`.
///
/// Functions that cannot be decompiled are skipped, without affecting the other XREFs. Returns the number of
/// string uses in functions that were dumped.
///
/// # Errors
///
/// Returns the appropriate [`HaruspexError`] if the output files cannot be created, or if the Hex-Rays
/// decompiler license is not available for the target binary.
fn traverse_xrefs(
    idb: &IDB,
    addr: Address,
    dirpath: &Path,
    dumped: &mut DumpCache,
) -> Result<usize, HaruspexError> {
    let mut string_uses_count: usize = 0;

    for xref in iter::successors(idb.first_xref_to(addr, XRefQuery::ALL), XRef::next_to) {
        let from = xref.from();

        // If XREF is in a function, dump the function's pseudocode and type definitions,
        // otherwise only print its address.
        if let Some(func) = idb.function_at(from) {
            // Skip the function if it has the `thunk` attribute, and only count it if it was dumped.
            if !func.flags().contains(FunctionFlags::THUNK)
                && dump_function_pseudocode(idb, &func, from, dirpath, dumped)?
            {
                string_uses_count = string_uses_count.saturating_add(1);
            }
        } else {
            println!("{from:#X} in [unknown]");
        }
    }

    Ok(string_uses_count)
}

/// Dumps pseudocode of `func` into `dirpath` and prints XREF address, function name, and output path (or a
/// failure notice if `func` cannot be decompiled).
///
/// Alongside the `.c` pseudocode file, a sibling `.h` file with `func`'s type definitions is written
/// when any are available; if there are none, only the `.c` file is produced.
///
/// Each function is decompiled only once: `dumped` tracks the output files already written for each
/// function, which are reused (as is if already in `dirpath`, copied otherwise) for any further string use,
/// as well as the functions that failed to decompile, which are not retried.
///
/// Returns `true` if the pseudocode was dumped, or `false` if `func` could not be decompiled.
///
/// # Errors
///
/// Returns [`HaruspexError`] if the output files cannot be created, or if the Hex-Rays decompiler license
/// is not available for the target binary.
fn dump_function_pseudocode(
    idb: &IDB,
    func: &Function<'_>,
    from: Address,
    dirpath: &Path,
    dumped: &mut DumpCache,
) -> Result<bool, HaruspexError> {
    let func_name = func.name().unwrap_or_else(|| "[no name]".into());
    let output_path = output_path_for_function(func, dirpath);

    // Decompile the function on first use only. `None` means it failed to decompile, so it isn't retried.
    let cached = match dumped.entry(func.start_address()) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            entry.insert(DumpedFunction::decompile_to(idb, func, &output_path)?)
        }
    };

    let Some(dumped_func) = cached.as_mut() else {
        println!("{from:#X} in {func_name} -> [decompilation failed]");
        return Ok(false);
    };

    // Reuse the output files if the function was already dumped for another string.
    dumped_func.copy_to(&output_path)?;

    if dumped_func.has_header {
        println!(
            "{from:#X} in {func_name} -> `{}` + `{}`",
            output_path.display(),
            output_path
                .with_extension("h")
                .file_name()
                .map(OsStr::to_string_lossy)
                .unwrap_or_default()
        );
    } else {
        println!("{from:#X} in {func_name} -> `{}`", output_path.display());
    }

    Ok(true)
}

/// Returns `true` if `err` means that the Hex-Rays decompiler license is not available for the target binary.
fn is_license_error(err: &IDAError) -> bool {
    matches!(err, IDAError::HexRays(hexrays_err) if hexrays_err.code() == HexRaysErrorCode::License)
}

/// Returns the name of the output subdirectory for `string` at `addr`, i.e., `_{addr:X}_{sanitized_string}_`.
///
/// Only the printable chars in `string` are kept, reserved chars (including path separators) are replaced, and
/// the result is truncated by haruspex's `sanitize_filename`, so that the name is always a single path component
/// inside the output directory.
fn string_dirname(addr: Address, string: &str) -> String {
    format!(
        "_{addr:X}_{}_",
        sanitize_filename(&filter_printable_chars(string))
    )
}

/// Creates the parent directory of `filepath` and all its missing ancestors, if `filepath` has a parent.
///
/// # Errors
///
/// Returns [`io::Error`] if the directory cannot be created.
fn create_parent_dir(filepath: &Path) -> io::Result<()> {
    filepath.parent().map_or(Ok(()), fs::create_dir_all)
}

/// Returns only the printable chars in `string`, i.e., ASCII graphic chars and spaces.
fn filter_printable_chars(string: &str) -> String {
    string
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
        .collect()
}

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]
mod tests {
    use std::path::Component;
    use std::{env, process};

    use super::*;

    /// Returns a fresh, empty temporary directory scoped to `label` and the current process.
    fn test_dir(label: &str) -> io::Result<PathBuf> {
        let dir = env::temp_dir().join(format!("augur_{label}_{}", process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Writes a `.c` file (and optionally a `.h` file) at `source` and returns the matching [`DumpedFunction`].
    fn dumped_function(source: PathBuf, has_header: bool) -> io::Result<DumpedFunction> {
        fs::write(&source, "pseudocode")?;
        if has_header {
            fs::write(source.with_extension("h"), "types")?;
        }
        Ok(DumpedFunction { source, has_header })
    }

    #[test]
    fn copy_to_does_nothing_if_files_are_already_in_place() -> io::Result<()> {
        let dir = test_dir("copy_in_place")?;
        let source = dir.join("func@1000.c");
        let mut dumped_func = dumped_function(source.clone(), true)?;

        dumped_func.copy_to(&source)?;

        assert_eq!(dumped_func.source, source, "source should be unchanged");
        assert_eq!(
            dir.read_dir()?.count(),
            2,
            "no files should be added or removed"
        );
        fs::remove_dir_all(&dir)
    }

    #[test]
    fn copy_to_copies_source_and_header_and_tracks_the_copy() -> io::Result<()> {
        let dir = test_dir("copy_header")?;
        let dirpath = dir.join("string_b");
        fs::create_dir_all(&dirpath)?;
        let mut dumped_func = dumped_function(dir.join("func@1000.c"), true)?;
        let output_path = dirpath.join("func@1000.c");

        dumped_func.copy_to(&output_path)?;

        assert_eq!(
            fs::read_to_string(&output_path)?,
            "pseudocode",
            "source file should be copied"
        );
        assert_eq!(
            fs::read_to_string(output_path.with_extension("h"))?,
            "types",
            "header file should be copied"
        );
        assert_eq!(
            dumped_func.source, output_path,
            "source should point at the copy, so that further uses of the same string don't copy it again"
        );
        fs::remove_dir_all(&dir)
    }

    #[test]
    fn copy_to_without_header_copies_only_source() -> io::Result<()> {
        let dir = test_dir("copy_no_header")?;
        let dirpath = dir.join("string_b");
        fs::create_dir_all(&dirpath)?;
        let mut dumped_func = dumped_function(dir.join("func@1000.c"), false)?;
        let output_path = dirpath.join("func@1000.c");

        dumped_func.copy_to(&output_path)?;

        assert!(output_path.is_file(), "source file should be copied");
        assert!(
            !output_path.with_extension("h").exists(),
            "no header file should be created"
        );
        fs::remove_dir_all(&dir)
    }

    #[test]
    fn copy_to_creates_missing_output_directory() -> io::Result<()> {
        let dir = test_dir("copy_missing_dir")?;
        let dirpath = dir.join("string_b");
        let mut dumped_func = dumped_function(dir.join("func@1000.c"), false)?;
        let output_path = dirpath.join("func@1000.c");

        dumped_func.copy_to(&output_path)?;

        assert!(dirpath.is_dir(), "output directory should be created");
        assert!(output_path.is_file(), "source file should be copied");
        fs::remove_dir_all(&dir)
    }

    #[test]
    fn string_dirname_wraps_uppercase_hex_address_and_string() {
        assert_eq!(
            string_dirname(0xDEAD_BEEF, "type ERROR"),
            "_DEADBEEF_type ERROR_",
            "wrong directory name format"
        );
    }

    #[test]
    fn string_dirname_strips_non_printable_chars() {
        assert_eq!(
            string_dirname(0x1000, "line\n\tbreak\x00"),
            "_1000_linebreak_",
            "non-printable chars should be stripped"
        );
    }

    #[test]
    fn string_dirname_does_not_allow_path_traversal() {
        let name = string_dirname(0x1000, "../../etc/passwd");
        assert!(
            !name.contains(['/', '.']),
            "path separators and dots should be replaced: {name}"
        );
        assert!(
            matches!(
                Path::new(&name).components().collect::<Vec<_>>().as_slice(),
                [Component::Normal(_)]
            ),
            "name should be a single normal path component: {name}"
        );
    }

    #[test]
    fn filter_printable_chars_keeps_ascii_graphic_chars() {
        assert_eq!(
            filter_printable_chars("hello!@#$%^&*()"),
            "hello!@#$%^&*()",
            "ascii graphic chars should be kept"
        );
    }

    #[test]
    fn filter_printable_chars_keeps_space() {
        assert_eq!(
            filter_printable_chars("hello world"),
            "hello world",
            "space should be kept"
        );
    }

    #[test]
    fn filter_printable_chars_strips_control_chars() {
        assert_eq!(
            filter_printable_chars("hel\x00lo\x01\x1f"),
            "hello",
            "control chars should be stripped"
        );
    }

    #[test]
    fn filter_printable_chars_strips_nul_bytes() {
        assert_eq!(
            filter_printable_chars("foo\x00bar"),
            "foobar",
            "nul bytes should be stripped"
        );
    }

    #[test]
    fn filter_printable_chars_strips_non_ascii() {
        assert_eq!(
            filter_printable_chars("caf\u{00e9}"),
            "caf",
            "non-ascii chars should be stripped"
        );
    }

    #[test]
    fn filter_printable_chars_on_empty_string_produces_empty_string() {
        assert_eq!(
            filter_printable_chars(""),
            "",
            "empty input should produce empty output"
        );
    }

    #[test]
    fn filter_printable_chars_on_all_non_printable_chars_produces_empty_string() {
        assert_eq!(
            filter_printable_chars("\x00\x01\x02\x03"),
            "",
            "all non-printable chars should produce empty string"
        );
    }
}
