use std::fs;
use std::path::Path;

use walkdir::WalkDir;

/// Custom harness for integration tests
fn main() -> anyhow::Result<()> {
    // Target binary path
    const FILENAME: &str = "./tests/bin/ls";
    // Expected number of string usages in functions
    const N_USAGES: usize = 27;
    // Expected number of subdirectories
    const N_SUBDIRS: usize = 26;
    // Expected number of files in the output directory and all subdirectories
    const N_FILES: usize = N_USAGES + N_SUBDIRS + 1;

    // Remove IDB file if it exists
    let idb_path = &format!("{FILENAME}.i64");
    let idb_path = Path::new(idb_path);
    if idb_path.is_file() {
        fs::remove_file(idb_path)?;
    }

    // Remove output directory if it exists
    let filepath = Path::new(FILENAME);
    let dirpath = filepath.with_extension("str");
    if dirpath.exists() {
        fs::remove_dir_all(&dirpath)?;
    }

    // Run augur and check the number of string usages in functions
    let n_decomp = augur::run(Path::new(FILENAME))?;
    println!();
    print!("[*] Checking number of string usages in functions... ");
    assert_eq!(n_decomp, N_USAGES);
    println!("Ok.");

    // Check the number of created subdirectories in the output directory
    print!("[*] Checking number of subdirectories in output directory... ");
    assert_eq!(dirpath.read_dir()?.count(), N_SUBDIRS);
    println!("Ok.");

    // Check the number of created files in the output directory and all subdirectories
    print!("[*] Checking number of files in output directory and all subdirectories... ");
    assert_eq!(WalkDir::new(&dirpath).into_iter().count(), N_FILES);
    println!("Ok.");

    // Remove output directory at the end
    if dirpath.exists() {
        fs::remove_dir_all(&dirpath)?;
    }

    println!();
    Ok(())
}
