//! tests/main.rs.

use std::fs;
use std::path::Path;

use walkdir::WalkDir;

/// Custom harness for integration tests.
#[expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]
fn main() -> anyhow::Result<()> {
    // Target binary path.
    const FILENAME: &str = "./tests/data/dox_sig_parser";
    // Expected number of string uses in functions.
    const N_USES: usize = 18;
    // Expected number of subdirectories.
    const N_SUBDIRS: usize = 10;
    // Expected number of source files.
    const N_SOURCES: usize = 11;
    // Expected number of header files.
    const N_HEADERS: usize = 8;
    // Expected number of files in the output directory and all subdirectories.
    const N_FILES: usize = N_SUBDIRS + N_SOURCES + N_HEADERS + 1;

    // Remove the IDB file if it exists.
    let idb_path = Path::new(FILENAME).with_extension("i64");
    if idb_path.is_file() {
        fs::remove_file(idb_path)?;
    }

    // Remove the output directory if it exists.
    let filepath = Path::new(FILENAME);
    let dirpath = filepath.with_extension("str");
    if dirpath.exists() {
        fs::remove_dir_all(&dirpath)?;
    }

    // Run augur and check the number of string uses in functions.
    let n_decomp = augur::run(Path::new(FILENAME))?;
    eprintln!();
    eprint!("[*] Checking number of string uses in functions... ");
    assert_eq!(n_decomp, N_USES, "wrong number of string uses");
    eprintln!("Ok.");

    // Check the number of created subdirectories in the output directory.
    eprint!("[*] Checking number of subdirectories in output directory... ");
    assert_eq!(
        dirpath.read_dir()?.count(),
        N_SUBDIRS,
        "wrong number of subdirectories"
    );
    eprintln!("Ok.");

    // Check the number of created files in the output directory and all subdirectories.
    eprint!("[*] Checking number of files in output directory and all subdirectories... ");
    assert_eq!(
        WalkDir::new(&dirpath).into_iter().count(),
        N_FILES,
        "wrong number of files"
    );
    eprintln!("Ok.");

    // Check that string uses recovered only by decompiling all functions upfront are present.
    eprint!("[*] Checking string uses recovered via the decompiler are present... ");
    let recovered_dir = dirpath.join("_4020A8_Parsing type error at line %d__");
    assert!(
        recovered_dir.is_dir() && recovered_dir.read_dir()?.next().is_some(),
        "decompiler-recovered string use missing: {}",
        recovered_dir.display()
    );
    eprintln!("Ok.");

    // Check `run` disables the new Hex-Rays argument name hints by default.
    eprint!("[*] Checking argument name hints are disabled by default... ");
    let sub_file = dirpath.join("_402108__atoi_").join("sub_401B00@401B00.c");
    let sub_content = fs::read_to_string(&sub_file)?;
    assert!(
        sub_content.contains(r#"printf("%s(): Num can't be NULL.\n", "_atoi");"#),
        "output file `{}` contains argument name hints, expected them to be disabled",
        sub_file.display()
    );
    eprintln!("Ok.");

    // Spot-check a known output file: verify the naming scheme and that decompilation produced output.
    eprint!("[*] Checking known output file exists and is non-empty... ");
    let known_file = dirpath
        .join("_4020C8_type ERROR_")
        .join("sub_400C80@400C80.c");
    assert!(
        known_file.is_file(),
        "expected output file missing: {}",
        known_file.display()
    );
    assert!(
        known_file.metadata()?.len() > 0,
        "output file is empty: {}",
        known_file.display()
    );
    eprintln!("Ok.");

    // Check that a function with no type definitions to dump produces no header file.
    eprint!("[*] Checking function with no type definitions has no header file... ");
    let missing_header = dirpath
        .join("_4020C8_type ERROR_")
        .join("sub_401750@401750.h");
    assert!(
        !missing_header.exists(),
        "unexpected header file present: {}",
        missing_header.display()
    );
    eprintln!("Ok.");

    // Check that a function with type definitions produces a matching, non-empty header file.
    eprint!("[*] Checking known header file exists and is non-empty... ");
    let known_header = dirpath
        .join("_4020C8_type ERROR_")
        .join("sub_400C80@400C80.h");
    assert!(
        known_header.is_file(),
        "expected header file missing: {}",
        known_header.display()
    );
    assert!(
        known_header.metadata()?.len() > 0,
        "header file is empty: {}",
        known_header.display()
    );
    eprintln!("Ok.");

    // Remove the output directory at the end.
    if dirpath.exists() {
        fs::remove_dir_all(&dirpath)?;
    }

    eprintln!();
    Ok(())
}
