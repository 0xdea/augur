//!
//! augur - Tool to extract strings and related pseudo-code
//! Copyright (c) 2024-2025 Marco Ivaldi <raptor@0xdeadbeef.info>
//!
//! > "In fact I've actually triggered buffer overflows by just entering my real name."
//! >
//! > -- A.
//!
//! Augur is a blazing fast IDA Pro headless plugin that extracts strings and related pseudo-code
//! from a binary file.
//!
//! ## Features
//! * Blazing fast, headless user experience courtesy of IDA Pro 9 and Binarly's idalib Rust bindings.
//! * Support for binary targets for any architecture implemented by IDA Pro's Hex-Rays decompiler.
//! * Decompilation feature based on the `decompile_to_file` API exported by [haruspex](https://github.com/0xdea/haruspex).
//! * Pseudo-code of each function that references a specific string is stored in a separate directory.
//!
//! ## Blog post
//! * <https://security.humanativaspa.it/streamlining-vulnerability-research-with-ida-pro-and-rust> (*coming soon*)
//!
//! ## See also
//! * <https://github.com/0xdea/rhabdomancer>
//! * <https://github.com/0xdea/haruspex>
//! * <https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib>
//! * <https://github.com/binarly-io/idalib>
//!
//! ## Installing
//! The easiest way to get the latest release is via [crates.io](https://crates.io/crates/augur):
//! 1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
//! 2. Download and extract the IDA SDK (see <https://docs.hex-rays.com/developer-guide>).
//! 3. Install augur as follows:
//!     ```sh
//!     $ export IDASDKDIR=/path/to/idasdk90
//!     $ export IDADIR=/path/to/ida # if not set, the build script will check common locations
//!     $ cargo install augur
//!     ```
//!
//! ## Compiling
//! Alternatively, you can build from [source](https://github.com/0xdea/augur):
//! 1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
//! 2. Download and extract the IDA SDK (see <https://docs.hex-rays.com/developer-guide>).
//! 3. Compile augur as follows:
//!     ```sh
//!     $ git clone https://github.com/0xdea/augur
//!     $ cd augur
//!     $ export IDASDKDIR=/path/to/idasdk90 # or edit .cargo/config.toml
//!     $ export IDADIR=/path/to/ida # if not set, the build script will check common locations
//!     $ cargo build --release
//!     ```
//!
//! ## Usage
//! 1. Make sure IDA Pro is properly configured with a valid license.
//! 2. Run augur as follows:
//!     ```sh
//!     $ augur <binary_file>
//!     ```
//! 3. Find the extracted pseudo-code of each decompiled function in the `binary_file.str` directory,
//!    organized by string:
//!     ```sh
//!     $ vim <binary_file>.str
//!     $ code <binary_file>.str
//!     ```
//!
//! ## Tested with
//! * IDA Pro 9.0.241217 on macOS arm64 and Linux x64.
//!
//! *Note: only the `unix` target family is currently supported, check [idalib](https://github.com/binarly-io/idalib)
//! documentation if you want to port it yourself to `windows` (or `wasm`).*
//!
//! ## Changelog
//! * <https://github.com/0xdea/augur/blob/master/CHANGELOG.md>
//!
//! ## TODO
//! * Implement support for the `windows` target family.
//!

#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/augur/master/.img/logo.png")]

#[cfg(not(unix))]
compile_error!("only the `unix` target family is currently supported");

use std::fs;
use std::ops::Deref;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use haruspex::{decompile_to_file, HaruspexError};
use idalib::decompiler::HexRaysErrorCode;
use idalib::idb::IDB;
use idalib::xref::{XRef, XRefQuery};
use idalib::{Address, IDAError};

/// Number of decompiled functions
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// IDA string newtype
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// Recursively traverse XREFs and dump related pseudo-code to output file
    fn traverse_xrefs(
        &self,
        idb: &IDB,
        xref: &XRef,
        addr: Address,
        dirpath: &Path,
    ) -> Result<(), HaruspexError> {
        // If XREF is in a function, dump the function's pseudo-code
        if let Some(f) = idb.function_at(xref.from()) {
            // Generate output directory name
            let string_printable = self.filter_printable_chars().replace(['.', '/', ' '], "_");
            let output_dir = format!("{addr:X}_{string_printable}");

            // Generate output file name
            let func_name = f.name().unwrap().replace(['.', '/'], "_");
            let output_file = format!("{func_name}@{:X}", f.start_address());

            // Generate output path
            let dirpath_new = dirpath.join(&output_dir);
            let output_path = dirpath_new.join(output_file).with_extension("c");

            // Create output directory if needed
            if !dirpath_new.exists() {
                fs::create_dir(&dirpath_new)?;
            }

            // Decompile function and write pseudo-code to output file
            decompile_to_file(idb, &f, &output_path)?;

            // Print XREF address, function name, and output path in case of successful decompilation
            println!("{:#X} in {func_name} -> {output_path:?}", xref.from());

            COUNTER.fetch_add(1, Ordering::Relaxed);
        } else {
            // If XREF is not in a function, simply print its location
            println!("{:#X} in <unknown>", xref.from());
        }

        // Process next XREF
        xref.next_to().map_or(Ok(()), |next| {
            self.traverse_xrefs(idb, &next, addr, dirpath)
        })
    }

    /// Take an `IDAString` as input and return a `String` that contains only the printable chars
    fn filter_printable_chars(&self) -> String {
        self.chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .collect()
    }
}

/// Extract strings and related pseudo-code from the binary at `filepath`, save them in
/// `filepath.str`, and return how many functions were decompiled, or an error in case
/// something goes wrong
pub fn run(filepath: &Path) -> anyhow::Result<usize> {
    // Open target binary and run auto-analysis
    println!("[*] Trying to analyze binary file {filepath:?}");
    if !filepath.is_file() {
        return Err(anyhow::anyhow!("invalid file path"));
    }
    let idb = IDB::open(filepath)?;
    println!("[+] Successfully analyzed binary file");
    println!();

    // Print binary file information
    println!("[-] Processor: {}", idb.processor().long_name(),);
    println!("[-] Compiler: {:?}", idb.meta().cc_id());
    println!("[-] File type: {:?}", idb.meta().filetype());
    println!();

    // Check if Hex-Rays decompiler is available
    if !idb.decompiler_available() {
        return Err(anyhow::anyhow!("decompiler is not available"));
    }

    // Create a new output directory, returning an error if it already exists and it's not empty
    let dirpath = filepath.with_extension("str");
    println!("[*] Preparing output directory {dirpath:?}");
    if dirpath.exists() {
        fs::remove_dir(&dirpath).map_err(|_| anyhow::anyhow!("output directory already exists"))?;
    }
    fs::create_dir_all(&dirpath)?;
    println!("[+] Output directory is ready");

    // Locate XREFs to strings in target binary and dump related pseudo-code
    println!();
    println!("[*] Finding cross-references to strings...");
    for i in 0..idb.strings().len() {
        // Extract string and its address
        let string: IDAString = idb.strings().get_by_index(i).unwrap().into();
        let addr = idb.strings().get_address_by_index(i).unwrap();
        println!("\n{addr:#X} {:?} ", string.as_ref());

        // Traverse XREFs to string and dump related pseudo-code to output file
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
                    // TODO test this at the end, e.g. don't create intermediate dirs; is cleanup needed BTW?
                    Err(e) => Err(e),
                }
            })?;
    }

    // Remove output directory and return an error in case no functions were decompiled
    if COUNTER.load(Ordering::Relaxed) == 0 {
        fs::remove_dir_all(&dirpath)?;
        return Err(anyhow::anyhow!(
            "no functions were decompiled, check your input file"
        ));
    }

    println!();
    println!("[+] Decompiled {COUNTER:?} functions into {dirpath:?}");
    println!("[+] Done processing binary file {filepath:?}");
    Ok(COUNTER.load(Ordering::Relaxed))
}
