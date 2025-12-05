#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/augur/master/.img/logo.png")]

use std::fs;
use std::ops::Deref;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Context;
use haruspex::{HaruspexError, decompile_to_file};
use idalib::decompiler::HexRaysErrorCode;
use idalib::func::FunctionFlags;
use idalib::idb::IDB;
use idalib::xref::{XRef, XRefQuery};
use idalib::{Address, IDAError};

/// Number of decompiled functions
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Reserved characters in filenames
#[cfg(unix)]
const RESERVED_CHARS: &[char] = &['.', '/'];
#[cfg(windows)]
const RESERVED_CHARS: &[char] = &['.', '/', '<', '>', ':', '"', '\\', '|', '?', '*'];

/// Maximum length of filenames
const MAX_FILENAME_LEN: usize = 64;

/// IDA string type that holds strings extracted from IDA's string list
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct IDAString(String);

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

impl IDAString {
    /// Recursively traverse XREFs and dump related pseudocode to the output file
    fn traverse_xrefs(
        &self,
        idb: &IDB,
        xref: &XRef,
        addr: Address,
        dirpath: &Path,
    ) -> Result<(), HaruspexError> {
        // If XREF is in a function, dump the function's pseudocode, otherwise only print its address
        if let Some(f) = idb.function_at(xref.from()) {
            // Skip the function if it has the `thunk` attribute
            if f.flags().contains(FunctionFlags::THUNK) {
                return Ok(());
            }

            // Generate output directory name
            let string_name = self.filter_printable_chars();
            let output_dir = format!(
                "{addr:X}_{}",
                string_name
                    .replace(RESERVED_CHARS, "_")
                    .chars()
                    .take(MAX_FILENAME_LEN)
                    .collect::<String>()
            );

            // Generate output file name
            let func_name = f.name().unwrap_or_else(|| "<no name>".into());
            let output_file = format!(
                "{}@{:X}",
                func_name
                    .replace(RESERVED_CHARS, "_")
                    .chars()
                    .take(MAX_FILENAME_LEN)
                    .collect::<String>(),
                f.start_address()
            );

            // Generate the output path
            let dirpath_sub = dirpath.join(&output_dir);
            let output_path = dirpath_sub.join(output_file).with_extension("c");

            // Create the output directory if needed
            if !dirpath_sub.exists() {
                fs::create_dir(&dirpath_sub)?;
            }

            // Decompile function and write pseudocode to the output file
            decompile_to_file(idb, &f, &output_path)?;

            // Print XREF address, function name, and output path in case of successful decompilation
            println!(
                "{:#X} in {func_name} -> `{}`",
                xref.from(),
                output_path.display()
            );
            COUNTER.fetch_add(1, Ordering::Relaxed);
        } else {
            // Print only XREF address
            println!("{:#X} in <unknown>", xref.from());
        }

        // Process next XREF
        xref.next_to().map_or(Ok(()), |next| {
            self.traverse_xrefs(idb, &next, addr, dirpath)
        })
    }

    /// Take an `IDAString` as input and return a `String` that contains only its printable chars
    fn filter_printable_chars(&self) -> String {
        self.chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .collect()
    }
}

/// Extract strings and pseudocode of each function that references them from the binary at
/// `filepath` and save them in `filepath.str`.
///
/// ## Errors
///
/// Returns how many functions were decompiled, or a generic error in case something goes wrong.
pub fn run(filepath: &Path) -> anyhow::Result<usize> {
    // Open the target binary and run auto-analysis
    println!("[*] Analyzing binary file `{}`", filepath.display());
    let idb = IDB::open(filepath)
        .with_context(|| format!("Failed to analyze binary file `{}`", filepath.display()))?;
    println!("[+] Successfully analyzed binary file");
    println!();

    // Print binary file information
    println!("[-] Processor: {}", idb.processor().long_name(),);
    println!("[-] Compiler: {:?}", idb.meta().cc_id());
    println!("[-] File type: {:?}", idb.meta().filetype());
    println!();

    // Ensure Hex-Rays decompiler is available
    anyhow::ensure!(idb.decompiler_available(), "Decompiler is not available");

    // Create a new output directory, returning an error if it already exists, and it's not empty
    let dirpath = filepath.with_extension("str");
    println!("[*] Preparing output directory `{}`", dirpath.display());
    if dirpath.exists() {
        fs::remove_dir(&dirpath).map_err(|_| anyhow::anyhow!("Output directory already exists"))?;
    }
    fs::create_dir_all(&dirpath)
        .with_context(|| format!("Failed to create directory `{}`", dirpath.display()))?;
    println!("[+] Output directory is ready");

    // Locate XREFs to strings in the target binary and dump related pseudocode
    println!();
    println!("[*] Finding cross-references to strings...");
    for i in 0..idb.strings().len() {
        // Extract string with its address
        let string: IDAString = idb
            .strings()
            .get_by_index(i)
            .context("Failed to get string content")?
            .into();
        let addr = idb
            .strings()
            .get_address_by_index(i)
            .context("Failed to get string address")?;
        println!("\n{addr:#X} {:?} ", string.as_ref());

        // Traverse XREFs to string and dump related pseudocode to the output file
        idb.first_xref_to(addr, XRefQuery::ALL)
            .map_or(Ok::<(), HaruspexError>(()), |xref| {
                match string.traverse_xrefs(&idb, &xref, addr, &dirpath) {
                    // Cleanup and return an error if Hex-Rays decompiler license is not available
                    Err(HaruspexError::DecompileFailed(IDAError::HexRays(e)))
                        if e.code() == HexRaysErrorCode::License =>
                    {
                        fs::remove_dir_all(&dirpath)?;
                        Err(IDAError::HexRays(e).into())
                    }

                    // Ignore other IDA errors and do nothing when XREF processing is finished
                    Err(HaruspexError::DecompileFailed(_)) | Ok(()) => Ok(()),

                    // Return any other error
                    Err(e) => Err(e),
                }
            })?;
    }

    // Remove the output directory and return an error in case no functions were decompiled
    if COUNTER.load(Ordering::Relaxed) == 0 {
        fs::remove_dir_all(&dirpath)
            .with_context(|| format!("Failed to remove directory `{}`", dirpath.display()))?;
        anyhow::bail!("No functions were decompiled, check your input file");
    }

    println!();
    println!(
        "[+] Found {COUNTER:?} string usages in functions, decompiled into `{}`",
        dirpath.display()
    );
    println!("[+] Done processing binary file `{}`", filepath.display());
    Ok(COUNTER.load(Ordering::Relaxed))
}
