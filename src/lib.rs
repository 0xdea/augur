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

// Standard library imports
use std::error::Error;

// External crate imports
// use ...;

// Internal imports
// use ...;

// const NAME: type = ...;

// static NAME: type = ...;

/// Dispatch to function implementing the selected action
pub fn run(action: &str) -> Result<(), Box<dyn Error>> {
    match action {
        "action1" => func1()?,
        _ => func2(action)?,
    }

    Ok(())
}

// Other functions ...

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
