#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/augur/master/.img/logo.png")]

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ffi::OsStr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{fs, io};

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
    /// Decompiles `func` and writes its output files at `output_path` in `dirpath`, creating `dirpath` only
    /// once there is something to write in it.
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
        dirpath: &Path,
        output_path: &Path,
    ) -> Result<Option<Self>, HaruspexError> {
        let cfunc = match idb.decompile(func) {
            Ok(cfunc) => cfunc,

            // The Hex-Rays decompiler license is not available.
            Err(IDAError::HexRays(err)) if err.code() == HexRaysErrorCode::License => {
                return Err(IDAError::HexRays(err).into());
            }

            // The function can't be decompiled.
            Err(_) => return Ok(None),
        };

        // Only create the output directory once there is something to write in it.
        fs::create_dir_all(dirpath)?;
        dump_cfunc_pseudocode_to_file(&cfunc, output_path)?;

        let has_header =
            match dump_cfunc_types_to_file(idb, &cfunc, output_path.with_extension("h")) {
                Ok(()) => true,

                // The Hex-Rays decompiler license is not available.
                Err(HaruspexError::DecompileFailed(IDAError::HexRays(err)))
                    if err.code() == HexRaysErrorCode::License =>
                {
                    return Err(IDAError::HexRays(err).into());
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

    /// Makes the output files available at `output_path` in `dirpath`, copying them from their previous
    /// location unless they are already in place, then tracks the copy so the files aren't copied again.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the output directory cannot be created or the output files cannot be copied.
    fn copy_to(&mut self, dirpath: &Path, output_path: &Path) -> io::Result<()> {
        if self.source != output_path {
            fs::create_dir_all(dirpath)?;
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

/// IDA string type that holds strings extracted from IDA's string list.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct IDAString(String);

impl IDAString {
    /// Iteratively traverses XREFs and dumps related pseudocode and type definitions to the output file.
    ///
    /// Functions that cannot be decompiled are skipped, without affecting the other XREFs.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`HaruspexError`] if the output file cannot be created, or if the Hex-Rays
    /// decompiler license is not available for the target binary.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "`usize` can hardly overflow here"
    )]
    fn traverse_xrefs(
        &self,
        idb: &IDB,
        first_xref: XRef<'_>,
        addr: Address,
        dirpath: &Path,
        string_uses_count: &mut usize,
        dumped: &mut HashMap<Address, Option<DumpedFunction>>,
    ) -> Result<(), HaruspexError> {
        let string_name = self.filter_printable_chars();
        let dirpath_sub = dirpath.join(format!("_{addr:X}_{}_", sanitize_filename(&string_name)));

        let mut current = Some(first_xref);

        while let Some(xref) = current {
            let from = xref.from();

            // If XREF is in a function, dump the function's pseudocode and type definitions,
            // otherwise only print its address.
            if let Some(func) = idb.function_at(from) {
                // Skip the function if it has the `thunk` attribute, and only count it if it was dumped.
                if !func.flags().contains(FunctionFlags::THUNK)
                    && dump_function_pseudocode(idb, &func, from, &dirpath_sub, dumped)?
                {
                    *string_uses_count += 1;
                }
            } else {
                println!("{from:#X} in [unknown]");
            }
            current = xref.next_to();
        }

        Ok(())
    }

    /// Takes an [`IDAString`] as input and returns a [`String`] that contains only its printable chars.
    fn filter_printable_chars(&self) -> String {
        self.chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .collect()
    }
}

impl AsRef<str> for IDAString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for IDAString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for IDAString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Extracts strings and pseudocode/type definitions of each function that references them from the
/// binary at `filepath` and saves them in `filepath.str`.
///
/// Returns the number of locations where strings are referenced.
///
/// # Errors
///
/// Returns [`anyhow::Error`] in case something goes wrong with analyzing the binary file or decompiling functions.
pub fn run(filepath: impl AsRef<Path>) -> anyhow::Result<usize> {
    let start = Instant::now();

    eprintln!(
        "[*] Analyzing binary file `{}`",
        filepath.as_ref().display()
    );
    let mut idb = IDB::open(&filepath).with_context(|| {
        format!(
            "Failed to analyze binary file `{}`",
            filepath.as_ref().display()
        )
    })?;
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
    let dirpath = filepath.as_ref().with_extension("str");
    prepare_output_dir(&dirpath)?;

    // Leverage the full power of IDA to recover strings during decompilation.
    eprintln!();
    eprintln!("[*] Decompiling all functions and recovering strings...");
    // Cleanup and return an error if the Hex-Rays decompiler license is not available.
    if let Err(err) = recover_strings(&mut idb) {
        fs::remove_dir_all(&dirpath)?;
        return Err(err.into());
    }

    let mut string_uses_count = 0;
    let mut dumped = HashMap::new();

    eprintln!();
    eprintln!("[*] Finding cross-references to strings...");
    // Iterate over strings with their addresses, skipping any invalid entry in the string list.
    #[expect(clippy::shadow_reuse, reason = "shadowing is convenient here")]
    for (addr, string) in idb.strings().iter() {
        let string = IDAString::from(string);
        println!("\n{addr:#X} {:?}", string.as_ref());

        // Traverse XREFs to string and dump the related pseudocode and type definitions to the output files.
        idb.first_xref_to(addr, XRefQuery::ALL)
            .map_or(Ok::<(), HaruspexError>(()), |xref| {
                match string.traverse_xrefs(
                    &idb,
                    xref,
                    addr,
                    &dirpath,
                    &mut string_uses_count,
                    &mut dumped,
                ) {
                    // Cleanup and return an error if the Hex-Rays decompiler license is not available.
                    Err(HaruspexError::DecompileFailed(IDAError::HexRays(err)))
                        if err.code() == HexRaysErrorCode::License =>
                    {
                        fs::remove_dir_all(&dirpath)?;
                        Err(IDAError::HexRays(err).into())
                    }

                    // Propagate any other error, or do nothing when XREF processing is finished.
                    result => result,
                }
            })?;
    }

    if string_uses_count == 0 {
        fs::remove_dir_all(&dirpath)
            .with_context(|| format!("Failed to remove directory `{}`", dirpath.display()))?;
        anyhow::bail!("No string uses were found, check your input file");
    }

    eprintln!();
    eprintln!(
        "[+] Found {string_uses_count} string uses in functions, decompiled into `{}`",
        dirpath.display()
    );
    eprintln!(
        "[+] Done processing binary file `{}` in {:.1} seconds",
        filepath.as_ref().display(),
        start.elapsed().as_secs_f64()
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
        if let Err(IDAError::HexRays(err)) = idb.decompile(&func)
            && err.code() == HexRaysErrorCode::License
        {
            return Err(IDAError::HexRays(err));
        }
    }

    // The decompiler queues new string items for auto-analysis, so wait for it before rebuilding.
    if !idb.auto_wait() {
        eprintln!("[!] Auto-analysis failed");
    }
    idb.strings().rebuild();

    Ok(())
}

/// Dumps pseudocode of `func` into `dirpath` and prints XREF address, function name, and output path.
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
    dumped: &mut HashMap<Address, Option<DumpedFunction>>,
) -> Result<bool, HaruspexError> {
    let func_name = func.name().unwrap_or_else(|| "[no name]".into());
    let output_path = output_path_for_function(func, dirpath);

    // Decompile the function on first use only. `None` means it failed to decompile, so it isn't retried.
    let cached = match dumped.entry(func.start_address()) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => entry.insert(DumpedFunction::decompile_to(
            idb,
            func,
            dirpath,
            &output_path,
        )?),
    };

    let Some(dumped_func) = cached.as_mut() else {
        println!("{from:#X} in {func_name} -> [decompilation failed]");
        return Ok(false);
    };

    // Reuse the output files if the function was already dumped for another string.
    dumped_func.copy_to(dirpath, &output_path)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_printable_chars_keeps_ascii_graphic_chars() {
        let s = IDAString::from("hello!@#$%^&*()".to_owned());
        assert_eq!(
            s.filter_printable_chars(),
            "hello!@#$%^&*()",
            "ascii graphic chars should be kept"
        );
    }

    #[test]
    fn filter_printable_chars_keeps_space() {
        let s = IDAString::from("hello world".to_owned());
        assert_eq!(
            s.filter_printable_chars(),
            "hello world",
            "space should be kept"
        );
    }

    #[test]
    fn filter_printable_chars_strips_control_chars() {
        let s = IDAString::from("hel\x00lo\x01\x1f".to_owned());
        assert_eq!(
            s.filter_printable_chars(),
            "hello",
            "control chars should be stripped"
        );
    }

    #[test]
    fn filter_printable_chars_strips_nul_bytes() {
        let s = IDAString::from("foo\x00bar".to_owned());
        assert_eq!(
            s.filter_printable_chars(),
            "foobar",
            "nul bytes should be stripped"
        );
    }

    #[test]
    fn filter_printable_chars_strips_non_ascii() {
        let s = IDAString::from("caf\u{00e9}".to_owned());
        assert_eq!(
            s.filter_printable_chars(),
            "caf",
            "non-ascii chars should be stripped"
        );
    }

    #[test]
    fn filter_printable_chars_on_empty_string_produces_empty_string() {
        let s = IDAString::from(String::new());
        assert_eq!(
            s.filter_printable_chars(),
            "",
            "empty input should produce empty output"
        );
    }

    #[test]
    fn filter_printable_chars_on_all_non_printable_chars_produces_empty_string() {
        let s = IDAString::from("\x00\x01\x02\x03".to_owned());
        assert_eq!(
            s.filter_printable_chars(),
            "",
            "all non-printable chars should produce empty string"
        );
    }
}
