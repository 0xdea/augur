// Standard library imports
use std::env;
use std::path::Path;
use std::process;

// External crate imports
// use ...;

// Internal imports
// use ...;

// const NAME: type = ...;

// static NAME: type = ...;

const PROG: &str = env!("CARGO_PKG_NAME");

fn main() {
    println!("{PROG} - TODO");
    println!("Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>");
    println!();

    // Force IDA Pro to stay quiet
    idalib::force_batch_mode();

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    let prog = Path::new(&args[0])
        .file_name()
        .unwrap()
        .to_str()
        .unwrap_or(PROG);

    let action = match args.len() {
        1 => "default",
        2 => &args[1].clone(),
        _ => "-",
    };
    if action.starts_with('-') {
        usage(prog);
    }

    // Let's do it
    match augur::run(action) {
        Ok(()) => (),
        Err(err) => {
            eprintln!("[!] Error: {err}");
            process::exit(1);
        }
    }
}

/// Print usage information and exit
fn usage(prog: &str) {
    println!("Usage:");
    println!(".\\{prog} TODO");
    println!("\nExamples:");
    println!(".\\{prog}");
    println!(".\\{prog} TODO");

    process::exit(1);
}
