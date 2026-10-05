#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/augur/master/.img/logo.png")]

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::Path;
use std::time::Instant;
use std::{fs, iter};

use anyhow::Context as _;
use haruspex::{
    ArgHintsMode, DumpedFunction, HaruspexError, decompile, decompile_to_file, function_name,
    output_path_for_function, prepare_output_dir, sanitize_filename,
};
use idalib::Address;
use idalib::func::{Function, FunctionFlags};
use idalib::idb::IDB;
use idalib::xref::{XRef, XRefQuery};

/// Output files of each function decompiled so far, keyed by function start
/// address.
///
/// `None` means that the function failed to decompile, so it isn't retried.
type DumpCache = HashMap<Address, Option<DumpedFunction>>;

/// Dumps pseudocode and type definitions of the functions that reference
/// strings, decompiling each function at most once per run.
struct FunctionDumper<'a> {
    /// IDB that contains the functions to dump.
    idb: &'a IDB,
    /// Output files of each function dumped so far.
    dumped: DumpCache,
}

impl<'a> FunctionDumper<'a> {
    /// Returns a dumper for the functions in `idb`, with no functions dumped yet.
    #[must_use]
    fn new(idb: &'a IDB) -> Self {
        Self {
            idb,
            dumped: DumpCache::default(),
        }
    }

    /// Dumps pseudocode and type definitions of each function that references
    /// the strings in the IDB into `dirpath`, organized by string.
    ///
    /// Returns the number of string uses in functions that were dumped, which
    /// may be zero.
    ///
    /// # Errors
    ///
    /// Returns [`HaruspexError`] if the output files cannot be created, or if the
    /// Hex-Rays decompiler license is not available for the target binary.
    fn dump_all(&mut self, dirpath: &Path) -> Result<usize, HaruspexError> {
        let mut string_uses_count = 0_usize;

        for (addr, string) in self.idb.strings().iter() {
            println!("\n{addr:#X} {string:?}");

            // Traverse XREFs to string and dump the related pseudocode and type
            // definitions to the output files.
            let string_dirpath = dirpath.join(string_dirname(addr, &string));
            let count = self.traverse_xrefs(addr, &string_dirpath)?;
            string_uses_count = string_uses_count.saturating_add(count);
        }

        Ok(string_uses_count)
    }

    /// Iteratively traverses the XREFs to the string at `addr`, and dumps
    /// pseudocode and type definitions of each referencing function into
    /// `dirpath`.
    ///
    /// Functions that cannot be decompiled are skipped, without affecting the
    /// other XREFs. Returns the number of string uses in functions that were
    /// dumped.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`HaruspexError`] if the output files cannot be
    /// created, or if the Hex-Rays decompiler license is not available for the
    /// target binary.
    fn traverse_xrefs(&mut self, addr: Address, dirpath: &Path) -> Result<usize, HaruspexError> {
        let idb = self.idb;
        let mut string_uses_count = 0_usize;

        for xref in iter::successors(idb.first_xref_to(addr, XRefQuery::ALL), XRef::next_to) {
            let from = xref.from();

            // If XREF is in a function, dump the function's pseudocode and type
            // definitions, otherwise only print its address.
            if let Some(func) = idb.function_at(from) {
                // Only count the string use if the function was dumped.
                if !func.flags().contains(FunctionFlags::THUNK)
                    && self.dump_function_pseudocode(&func, from, dirpath)?
                {
                    string_uses_count = string_uses_count.saturating_add(1);
                }
            } else {
                println!("{from:#X} in [unknown]");
            }
        }

        Ok(string_uses_count)
    }

    /// Dumps pseudocode of `func` into `dirpath` and prints XREF address,
    /// function name, and output path (or a failure notice if `func` cannot be
    /// decompiled).
    ///
    /// Alongside the `.c` pseudocode file, a sibling `.h` file with `func`'s type
    /// definitions is written when any are available; if there are none, only
    /// the `.c` file is produced.
    ///
    /// Each function is decompiled only once: the dumper tracks the output files
    /// already written for each function, which are reused (as is if already in
    /// `dirpath`, copied otherwise) for any further string use, as well as the
    /// functions that failed to decompile, which are not retried.
    ///
    /// Returns `true` if the pseudocode was dumped, or `false` if `func` could
    /// not be decompiled.
    ///
    /// # Errors
    ///
    /// Returns [`HaruspexError`] if the output files cannot be created, or if the
    /// Hex-Rays decompiler license is not available for the target binary.
    fn dump_function_pseudocode(
        &mut self,
        func: &Function<'_>,
        from: Address,
        dirpath: &Path,
    ) -> Result<bool, HaruspexError> {
        // Get the name only once, for both the output path and the output line.
        let func_name = function_name(func);
        let output_path = output_path_for_function(&func_name, func.start_address(), dirpath);

        // Decompile the function on first use only.
        let cached = match self.dumped.entry(func.start_address()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(decompile_to_file(self.idb, func, &output_path)?),
        };

        // `None` means the function failed to decompile, so it isn't retried.
        let Some(dumped_func) = cached.as_mut() else {
            println!("{from:#X} in {func_name} -> [decompilation failed]");
            return Ok(false);
        };

        // Reuse the output files if the function was already dumped for another
        // string.
        dumped_func.copy_to(&output_path)?;

        let pseudocode = dumped_func.pseudocode.display();
        match &dumped_func.types {
            Some(types) => println!(
                "{from:#X} in {func_name} -> `{pseudocode}` + `{}`",
                // A path built by `with_extension` always has a file name.
                types
                    .file_name()
                    .map_or(types.as_path(), Path::new)
                    .display()
            ),
            None => println!("{from:#X} in {func_name} -> `{pseudocode}`"),
        }

        Ok(true)
    }
}

/// Extracts strings and pseudocode/type definitions of each function that
/// references them from the binary at `filepath` and saves them in
/// `filepath.str`.
///
/// Returns the number of string uses in functions whose pseudocode was dumped.
///
/// # Errors
///
/// Returns [`anyhow::Error`] if the binary file cannot be analyzed, if the
/// decompiler or its license is not available, if the output directory already
/// exists and is not empty, if the output files cannot be created, or if no
/// string uses were found. On any error after the output directory is created,
/// the directory is removed.
pub fn run(filepath: impl AsRef<Path>) -> anyhow::Result<usize> {
    let start = Instant::now();
    let filepath = filepath.as_ref();

    eprintln!("[*] Analyzing binary file `{}`", filepath.display());
    let mut idb = IDB::open(filepath)
        .with_context(|| format!("failed to analyze binary file `{}`", filepath.display()))?;
    eprintln!("[+] Successfully analyzed binary file");
    eprintln!();

    eprintln!("[-] Processor: {}", idb.processor().long_name());
    eprintln!("[-] Compiler: {:?}", idb.meta().cc_id());
    eprintln!("[-] File type: {:?}", idb.meta().filetype());
    eprintln!();

    // Disable argument name hints, which also checks that a decompiler is
    // available.
    ArgHintsMode::Disabled.apply(&mut idb)?;

    // Create a new output directory, returning an error if it already exists and
    // it's not empty.
    let dirpath = filepath.with_extension("str");
    eprintln!("[*] Preparing output directory `{}`", dirpath.display());
    prepare_output_dir(&dirpath)?;
    eprintln!("[+] Output directory is ready");

    // Remove the output directory, which is empty or only partially populated, if
    // anything goes wrong, including when no string uses were found.
    let string_uses_count = extract_string_uses(&mut idb, &dirpath)
        .map_err(anyhow::Error::from)
        .and_then(|count| {
            anyhow::ensure!(
                count > 0,
                "no string uses were found, check your input file"
            );
            Ok(count)
        })
        .inspect_err(|_| {
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

/// Recovers strings, then dumps pseudocode and type definitions of each
/// function that references them into `dirpath`, organized by string.
///
/// Returns the number of string uses in functions that were dumped, which may
/// be zero.
///
/// # Errors
///
/// Returns [`HaruspexError`] if the output files cannot be created, or if the
/// Hex-Rays decompiler license is not available for the target binary.
fn extract_string_uses(idb: &mut IDB, dirpath: &Path) -> Result<usize, HaruspexError> {
    // Leverage the full power of IDA to recover strings during decompilation.
    eprintln!();
    eprintln!("[*] Decompiling all functions and recovering strings...");
    recover_strings(idb)?;

    eprintln!();
    eprintln!("[*] Finding cross-references to strings...");
    FunctionDumper::new(idb).dump_all(dirpath)
}

/// Decompiles all functions in the IDB to let IDA recover additional strings,
/// ignoring decompilation errors, then rebuilds the string list.
///
/// # Errors
///
/// Returns [`HaruspexError`] if no function can be decompiled, e.g., because
/// the Hex-Rays decompiler license is not available for the target binary.
fn recover_strings(idb: &mut IDB) -> Result<(), HaruspexError> {
    for (_id, func) in idb.functions() {
        if func.flags().contains(FunctionFlags::THUNK) {
            continue;
        }

        // Bail out early if no function can be decompiled, ignore functions that
        // can't be decompiled.
        match decompile(idb, &func) {
            Ok(_) | Err(HaruspexError::Decompile { .. }) => {}
            Err(err) => return Err(err),
        }
    }

    // The decompiler queues new string items for auto-analysis, so wait for it
    // before rebuilding.
    if !idb.auto_wait() {
        eprintln!("[!] Auto-analysis failed");
    }
    idb.strings().rebuild();

    Ok(())
}

/// Returns the name of the output subdirectory for `string` at `addr`, i.e.,
/// `_{addr:X}_{sanitized_string}_`.
///
/// Only the printable chars in `string` are kept, reserved chars (including
/// path separators) are replaced, and the result is truncated by haruspex's
/// [`sanitize_filename`], so that the name is always a single path component
/// inside the output directory.
#[must_use]
fn string_dirname(addr: Address, string: &str) -> String {
    format!(
        "_{addr:X}_{}_",
        sanitize_filename(&filter_printable_chars(string))
    )
}

/// Returns only the printable chars in `string`, i.e., ASCII graphic chars and
/// spaces.
#[must_use]
fn filter_printable_chars(string: &str) -> String {
    string
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Component;

    use super::*;

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
    fn filter_printable_chars_strips_non_ascii() {
        assert_eq!(
            filter_printable_chars("caf\u{00e9}"),
            "caf",
            "non-ascii chars should be stripped"
        );
    }
}
