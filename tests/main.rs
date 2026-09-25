//! tests/main.rs.

#![expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use walkdir::WalkDir;

/// Target binary with string uses.
const DOX_SIG_PARSER: &str = "./tests/data/dox_sig_parser";
/// Target binary without string uses.
const NO_STRINGS: &str = "./tests/data/no_strings";

/// Expected number of string uses in functions in `DOX_SIG_PARSER`.
const N_USES: usize = 18;
/// Expected number of subdirectories in the output directory of `DOX_SIG_PARSER`.
const N_SUBDIRS: usize = 10;
/// Expected number of source files in the output directory of `DOX_SIG_PARSER`.
const N_SOURCES: usize = 11;
/// Expected number of header files in the output directory of `DOX_SIG_PARSER`.
const N_HEADERS: usize = 8;
/// Expected number of files in the output directory of `DOX_SIG_PARSER` and all subdirectories, including
/// the root.
const N_FILES: usize = N_SUBDIRS + N_SOURCES + N_HEADERS + 1;

/// Custom harness for integration tests.
fn main() -> anyhow::Result<()> {
    test_binary_with_string_uses()?;
    test_binary_without_string_uses()?;

    eprintln!();
    Ok(())
}

/// Runs augur against a binary with string uses and checks its output.
fn test_binary_with_string_uses() -> anyhow::Result<()> {
    let dirpath = reset_output(DOX_SIG_PARSER)?;

    let n_uses = augur::run(DOX_SIG_PARSER)?;
    eprintln!();
    check_number_of_string_uses(n_uses);
    check_number_of_subdirectories(&dirpath)?;
    check_number_of_files(&dirpath);
    check_recovered_string_uses(&dirpath)?;
    check_arg_hints_disabled(&dirpath)?;
    check_known_output_file(&dirpath)?;
    check_missing_header_file(&dirpath);
    check_known_header_file(&dirpath)?;

    // Remove the output directory at the end.
    fs::remove_dir_all(&dirpath)?;
    eprintln!();
    Ok(())
}

/// Runs augur against a binary without string uses and checks that it fails cleanly.
fn test_binary_without_string_uses() -> anyhow::Result<()> {
    let dirpath = reset_output(NO_STRINGS)?;

    let result = augur::run(NO_STRINGS);
    eprintln!();
    check_no_string_uses_error(result)?;
    check_output_dir_removed(&dirpath);
    Ok(())
}

/// Removes the IDB file and the output directory of the binary at `filename`, if they exist.
///
/// Returns the path of the output directory.
fn reset_output(filename: &str) -> anyhow::Result<PathBuf> {
    let filepath = Path::new(filename);

    let idb_path = filepath.with_extension("i64");
    if idb_path.is_file() {
        fs::remove_file(idb_path)?;
    }

    let dirpath = filepath.with_extension("str");
    if dirpath.exists() {
        fs::remove_dir_all(&dirpath)?;
    }
    Ok(dirpath)
}

/// Checks the number of string uses in functions.
fn check_number_of_string_uses(n_uses: usize) {
    eprint!("[*] Checking number of string uses in functions... ");
    assert_eq!(n_uses, N_USES, "wrong number of string uses");
    eprintln!("Ok.");
}

/// Checks the number of created subdirectories in the output directory.
fn check_number_of_subdirectories(dirpath: &Path) -> anyhow::Result<()> {
    eprint!("[*] Checking number of subdirectories in output directory... ");
    assert_eq!(
        dirpath.read_dir()?.count(),
        N_SUBDIRS,
        "wrong number of subdirectories"
    );
    eprintln!("Ok.");
    Ok(())
}

/// Checks the number of created files in the output directory and all subdirectories.
fn check_number_of_files(dirpath: &Path) {
    eprint!("[*] Checking number of files in output directory and all subdirectories... ");
    assert_eq!(
        WalkDir::new(dirpath).into_iter().count(),
        N_FILES,
        "wrong number of files"
    );
    eprintln!("Ok.");
}

/// Checks that string uses recovered only by decompiling all functions upfront are present.
fn check_recovered_string_uses(dirpath: &Path) -> anyhow::Result<()> {
    eprint!("[*] Checking string uses recovered via the decompiler are present... ");
    let recovered_dir = dirpath.join("_4020A8_Parsing type error at line %d__");
    assert!(
        recovered_dir.is_dir() && recovered_dir.read_dir()?.next().is_some(),
        "decompiler-recovered string use missing: {}",
        recovered_dir.display()
    );
    eprintln!("Ok.");
    Ok(())
}

/// Checks that `run` disables the new Hex-Rays argument name hints by default.
fn check_arg_hints_disabled(dirpath: &Path) -> anyhow::Result<()> {
    eprint!("[*] Checking argument name hints are disabled by default... ");
    let sub_file = dirpath.join("_402108__atoi_").join("sub_401B00@401B00.c");
    let sub_content = fs::read_to_string(&sub_file)?;
    assert!(
        sub_content.contains(r#"printf("%s(): Num can't be NULL.\n", "_atoi");"#),
        "output file `{}` contains argument name hints, expected them to be disabled",
        sub_file.display()
    );
    eprintln!("Ok.");
    Ok(())
}

/// Spot-checks a known output file: verifies the naming scheme and that decompilation produced output.
fn check_known_output_file(dirpath: &Path) -> anyhow::Result<()> {
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
    Ok(())
}

/// Checks that a function with no type definitions to dump produces no header file.
fn check_missing_header_file(dirpath: &Path) {
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
}

/// Checks that a function with type definitions produces a matching, non-empty header file.
fn check_known_header_file(dirpath: &Path) -> anyhow::Result<()> {
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
    Ok(())
}

/// Checks that `run` returns the expected error for a binary without string uses.
fn check_no_string_uses_error(result: anyhow::Result<usize>) -> anyhow::Result<()> {
    eprint!("[*] Checking binary without string uses returns an error... ");
    let err = result
        .err()
        .context("expected an error for a binary without string uses")?;
    assert!(
        err.to_string().contains("No string uses were found"),
        "wrong error returned: {err:#}"
    );
    eprintln!("Ok.");
    Ok(())
}

/// Checks that the output directory was removed on error.
fn check_output_dir_removed(dirpath: &Path) {
    eprint!("[*] Checking output directory is removed on error... ");
    assert!(
        !dirpath.exists(),
        "output directory left behind: {}",
        dirpath.display()
    );
    eprintln!("Ok.");
}
