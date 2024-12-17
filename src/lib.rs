//!
//! augur - TODO
//! Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>
//!
//! > "In fact I've actually triggered buffer overflows by just entering my real name."
//! >
//! > -- A.
//!
//! TODO
//!
//! ## Features
//! * TODO
//!
//! ## Blog post
//! * TODO
//!
//! ## See also
//! * TODO
//!
//! ## Installing
//! The easiest way to get the latest release is via [crates.io](https://crates.io/crates/augur):
//! ```sh
//! TODO
//! ```
//!
//! ## Compiling
//! Alternatively, you can build from [source](https://github.com/0xdea/augur):
//! ```sh
//! TODO
//! ```
//!
//! ## Usage
//! ```sh
//! TODO
//! ```
//!
//! ## Examples
//! TODO:
//! ```sh
//! TODO
//! ```
//!
//! TODO:
//! ```sh
//! TODO
//! ```
//!
//! ## Tested on/with
//! * TODO
//!
//! ## Changelog
//! * <https://github.com/0xdea/augur/blob/master/CHANGELOG.md>
//!
//! ## TODO
//! * TODO
//!

#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/augur/master/.img/logo.png")]

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use idalib::idb::IDB;
use idalib::xref::XRefQuery;
use idalib::Address;

/// TODO
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// TODO
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

    // Locate cross-references to strings in target binary
    println!();
    println!("[*] Finding cross-references to strings...");
    for i in 0..idb.strings().len() {
        let s = idb.strings().get_by_index(i).unwrap();
        let addr = idb.strings().get_address_by_index(i).unwrap();

        // TODO
        println!("\n{addr:#x} {s:?} ");
        get_xrefs(&idb, addr)?; // TODO handle error gracefully, don't stop

        // TODO check decompiler license

        /*
        // Traverse XREFs and mark call locations
        idb.first_xref_to(func.start_address(), XRefQuery::ALL)
            .map_or(Ok(()), |cur| Self::traverse_xrefs(idb, &cur, &desc))
         */
    }

    // TODO: find strings, XREFs, mark? (in case use open_with above), use `haruspex::decompile_to_file`

    // Remove output directory and return an error in case no functions were decompiled
    if COUNTER.load(Ordering::Relaxed) == 0 {
        fs::remove_dir(&dirpath)?;
        return Err(anyhow::anyhow!(
            "no functions were decompiled, check your input file"
        ));
    }

    Ok(COUNTER.load(Ordering::Relaxed))
}

fn get_xrefs(idb: &IDB, addr: Address) -> anyhow::Result<()> {
    let mut cur = idb
        .first_xref_to(addr, XRefQuery::ALL)
        .ok_or_else(|| anyhow::anyhow!("no xrefs to address {addr:#x}"))?;

    loop {
        // Print address with caller function name if available
        let caller = idb
            .function_at(cur.from())
            .map_or("<unknown>".to_string(), |func| func.name().unwrap());
        println!("{:#x} in {}", cur.from(), caller);
        //println!("{:#x}", cur.from());

        // TODO: only decompile functions, do it directly or with iterator, or collection?

        match cur.next_to() {
            Some(next) => cur = next,
            None => break,
        }
    }

    Ok(())
}
