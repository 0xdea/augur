//!
//! augur - TODO
//! Copyright (c) 2024-2025 Marco Ivaldi <raptor@0xdeadbeef.info>
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

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{fs, process};

use haruspex::{decompile_to_file, HaruspexError};
use idalib::decompiler::HexRaysErrorCode;
use idalib::idb::IDB;
use idalib::xref::XRefQuery;
use idalib::{Address, IDAError};

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
        match get_xrefs(&idb, addr, &s, &dirpath) {
            Ok(()) => { /* TODO print stuff here? */ }
            Err(_) => continue, // TODO differentiate other possible errors, e.g. decompile errors vs. no xrefs -> create our own error type like we did in Haruspex? + test this at the end, e.g. don't create intermediate dirs
        }

        // TODO check decompiler license

        /*
        // Traverse XREFs and mark call locations
        idb.first_xref_to(func.start_address(), XRefQuery::ALL)
            .map_or(Ok(()), |cur| Self::traverse_xrefs(idb, &cur, &desc))
         */
    }

    // TODO: find strings, XREFs, mark? (in case use open_with above), use `haruspex::decompile_to_file`
    // TODO: print final output with counter

    // Remove output directory and return an error in case no functions were decompiled
    if COUNTER.load(Ordering::Relaxed) == 0 {
        fs::remove_dir(&dirpath)?;
        return Err(anyhow::anyhow!(
            "no functions were decompiled, check your input file"
        ));
    }

    Ok(COUNTER.load(Ordering::Relaxed))
}

// TODO also rename, better manage all of these params, maybe in a struct
fn get_xrefs(idb: &IDB, addr: Address, string: &str, dirpath: &Path) -> anyhow::Result<()> {
    let mut cur = idb
        .first_xref_to(addr, XRefQuery::ALL)
        .ok_or_else(|| anyhow::anyhow!("no xrefs to address {addr:#x}"))?; // TODO map_or badaddr like in rhandomancer?

    loop {
        // TODO, refactor to make recursive calls like in rhabdomancer? add comment
        if let Some(f) = idb.function_at(cur.from()) {
            // Generate output directory name
            let string_printable = filter_printable_chars(string).replace(['.', '/', ' '], "_");
            let output_dir = format!("{addr:x}_{string_printable}");

            // Generate output file name
            let func_name = f.name().unwrap().replace(['.', '/'], "_");
            let output_file = format!("{func_name}@{:x}", f.start_address());

            // Generate output path
            let dirpath_new = dirpath.join(&output_dir);
            let output_path = dirpath_new.join(output_file).with_extension("c");

            // Create output directory if needed
            if !dirpath_new.exists() {
                fs::create_dir(&dirpath_new)?;
            }

            // Decompile function and write pseudo-code to output file
            match decompile_to_file(idb, &f, &output_path) {
                // Print XREF address, function name, and output path in case of successful decompilation
                Ok(()) => println!("{:#x} in {func_name} -> {output_path:?}", cur.from()),

                // Cleanup and bail if Hex-Rays decompiler license is not available
                Err(HaruspexError::Decompile(IDAError::HexRays(e)))
                    if e.code() == HexRaysErrorCode::License =>
                {
                    let _ = fs::remove_dir(dirpath_new);
                    let _ = fs::remove_dir(dirpath);
                    eprintln!("[!] Error: {e}");
                    process::exit(1); // TODO the idb remains open, I don't like this! try handling in run/main instead and see if this is prevented
                }

                // Ignore other IDA errors
                Err(HaruspexError::Decompile(_)) => continue,

                // Bail in case of any other error
                Err(e) => {
                    eprintln!("[!] Error: {e}");
                    process::exit(1);
                }
            }

            COUNTER.fetch_add(1, Ordering::Relaxed);
        } else {
            println!("{:#x} in <unknown>", cur.from());
        }

        match cur.next_to() {
            Some(next) => cur = next,
            None => break,
        }
    }

    Ok(())
}

// TODO make this a closure? or a method for a MyString type, perhaps aliased instead of a newtype
fn filter_printable_chars(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect()
}
