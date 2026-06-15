#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/augur/master/.img/logo.png")]

use std::fs;
use std::ops::Deref;
use std::path::Path;

use anyhow::Context as _;
use haruspex::{
    HaruspexError, decompile_to_file, output_path_for_function, prepare_output_dir,
    sanitize_filename,
};
use idalib::decompiler::HexRaysErrorCode;
use idalib::func::{Function, FunctionFlags};
use idalib::idb::IDB;
use idalib::xref::{XRef, XRefQuery};
use idalib::{Address, IDAError};

/// IDA string type that holds strings extracted from IDA's string list.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct IDAString(String);

impl IDAString {
    /// Iteratively traverses XREFs and dumps related pseudocode to the output file.
    ///
    /// ## Errors
    ///
    /// Returns an error if the output file cannot be created, the function cannot be decompiled, or if the Hex-Rays
    /// decompiler license is not available for the target binary.
    fn traverse_xrefs(
        &self,
        idb: &IDB,
        first_xref: XRef,
        addr: Address,
        dirpath: &Path,
        string_uses_count: &mut usize,
    ) -> Result<(), HaruspexError> {
        let string_name = self.filter_printable_chars();
        let dirpath_sub = dirpath.join(format!("_{addr:X}_{}_", sanitize_filename(&string_name)));

        let mut current = Some(first_xref);

        while let Some(xref) = current {
            let from = xref.from();

            // If XREF is in a function, dump the function's pseudocode, otherwise only print its address.
            if let Some(f) = idb.function_at(from) {
                // Skip the function if it has the `thunk` attribute.
                if !f.flags().contains(FunctionFlags::THUNK) {
                    dump_function_pseudocode(idb, &f, from, &dirpath_sub)?;
                    *string_uses_count += 1;
                }
            } else {
                // Print only XREF address.
                println!("{from:#X} in [unknown]");
            }
            current = xref.next_to();
        }

        Ok(())
    }

    /// Takes an `IDAString` as input and returns a `String` that contains only its printable chars.
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

/// Extracts strings and pseudocode of each function that references them from the binary at
/// `filepath` and saves them in `filepath.str`.
///
/// ## Errors
///
/// Returns the number of locations where strings are referenced, or an error in case something
/// goes wrong.
pub fn run(filepath: impl AsRef<Path>) -> anyhow::Result<usize> {
    // Open the target binary and run auto-analysis.
    println!(
        "[*] Analyzing binary file `{}`",
        filepath.as_ref().display()
    );
    let idb = IDB::open(&filepath).with_context(|| {
        format!(
            "Failed to analyze binary file `{}`",
            filepath.as_ref().display()
        )
    })?;
    println!("[+] Successfully analyzed binary file");
    println!();

    // Print binary file information.
    println!("[-] Processor: {}", idb.processor().long_name());
    println!("[-] Compiler: {:?}", idb.meta().cc_id());
    println!("[-] File type: {:?}", idb.meta().filetype());
    println!();

    // Ensure Hex-Rays decompiler is available.
    anyhow::ensure!(idb.decompiler_available(), "Decompiler is not available");

    // Create a new output directory, returning an error if it already exists, and it's not empty.
    let dirpath = filepath.as_ref().with_extension("str");
    prepare_output_dir(&dirpath)?;

    let mut string_uses_count = 0;

    // Locate XREFs to strings in the target binary and dump related pseudocode.
    println!();
    println!("[*] Finding cross-references to strings...");
    let strings = idb.strings();
    for i in 0..strings.len() {
        // Extract string with its address
        let string = IDAString::from(
            strings
                .get_by_index(i)
                .context("Failed to get string content")?,
        );
        let addr = strings
            .get_address_by_index(i)
            .context("Failed to get string address")?;
        println!("\n{addr:#X} {:?} ", string.as_ref());

        // Traverse XREFs to string and dump the related pseudocode to the output file.
        idb.first_xref_to(addr, XRefQuery::ALL)
            .map_or(Ok::<(), HaruspexError>(()), |xref| {
                match string.traverse_xrefs(&idb, xref, addr, &dirpath, &mut string_uses_count) {
                    // Cleanup and return an error if Hex-Rays decompiler license is not available.
                    Err(HaruspexError::DecompileFailed(IDAError::HexRays(e)))
                        if e.code() == HexRaysErrorCode::License =>
                    {
                        fs::remove_dir_all(&dirpath)?;
                        Err(IDAError::HexRays(e).into())
                    }

                    // Ignore other IDA errors and do nothing when XREF processing is finished.
                    Err(HaruspexError::DecompileFailed(_)) | Ok(()) => Ok(()),

                    // Return any other error.
                    Err(e) => Err(e),
                }
            })?;
    }

    // Remove the output directory and return an error in case no string uses were found.
    if string_uses_count == 0 {
        fs::remove_dir_all(&dirpath)
            .with_context(|| format!("Failed to remove directory `{}`", dirpath.display()))?;
        anyhow::bail!("No string uses were found, check your input file");
    }

    println!();
    println!(
        "[+] Found {string_uses_count} string uses in functions, decompiled into `{}`",
        dirpath.display()
    );
    println!(
        "[+] Done processing binary file `{}`",
        filepath.as_ref().display()
    );
    Ok(string_uses_count)
}

/// Dumps pseudocode of `func` into `dirpath` and prints XREF address, function name, and output path on success.
///
/// ## Errors
///
/// Returns an error if the output file cannot be created or the function cannot be decompiled.
fn dump_function_pseudocode(
    idb: &IDB,
    func: &Function,
    from: Address,
    dirpath: &Path,
) -> Result<(), HaruspexError> {
    // Build the output file path.
    let func_name = func.name().unwrap_or_else(|| "[no name]".into());
    let output_path = output_path_for_function(func, dirpath);

    // Create the output directory if needed.
    fs::create_dir_all(dirpath)?;

    // Decompile function and write pseudocode to the output file.
    decompile_to_file(idb, func, &output_path)?;

    // Print XREF address, function name, and output path in case of successful decompilation.
    println!("{from:#X} in {func_name} -> `{}`", output_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_keeps_ascii_graphic() {
        let s = IDAString::from("hello!@#$%^&*()".to_owned());
        assert_eq!(s.filter_printable_chars(), "hello!@#$%^&*()");
    }

    #[test]
    fn filter_keeps_space() {
        let s = IDAString::from("hello world".to_owned());
        assert_eq!(s.filter_printable_chars(), "hello world");
    }

    #[test]
    fn filter_strips_control_chars() {
        let s = IDAString::from("hel\x00lo\x01\x1f".to_owned());
        assert_eq!(s.filter_printable_chars(), "hello");
    }

    #[test]
    fn filter_strips_nul_bytes() {
        let s = IDAString::from("foo\x00bar".to_owned());
        assert_eq!(s.filter_printable_chars(), "foobar");
    }

    #[test]
    fn filter_strips_non_ascii() {
        let s = IDAString::from("caf\u{00e9}".to_owned());
        assert_eq!(s.filter_printable_chars(), "caf");
    }

    #[test]
    fn filter_empty_string() {
        let s = IDAString::from(String::new());
        assert_eq!(s.filter_printable_chars(), "");
    }

    #[test]
    fn filter_all_non_printable() {
        let s = IDAString::from("\x00\x01\x02\x03".to_owned());
        assert_eq!(s.filter_printable_chars(), "");
    }
}
