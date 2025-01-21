# augur

[![](https://img.shields.io/github/stars/0xdea/augur.svg?style=flat&color=yellow)](https://github.com/0xdea/augur)
[![](https://img.shields.io/github/forks/0xdea/augur.svg?style=flat&color=green)](https://github.com/0xdea/augur)
[![](https://img.shields.io/github/watchers/0xdea/augur.svg?style=flat&color=red)](https://github.com/0xdea/augur)
[![](https://img.shields.io/crates/v/augur?style=flat&color=green)](https://crates.io/crates/augur)
[![](https://img.shields.io/crates/d/augur?style=flat&color=red)](https://crates.io/crates/augur)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)
[![build](https://github.com/0xdea/augur/actions/workflows/build.yml/badge.svg)](https://github.com/0xdea/augur/actions/workflows/build.yml)
[![doc](https://github.com/0xdea/augur/actions/workflows/doc.yml/badge.svg)](https://github.com/0xdea/augur/actions/workflows/doc.yml)

> "In fact I've actually triggered buffer overflows by just entering my real name."
>
> -- A.

Augur is a blazing fast IDA Pro headless plugin that extracts strings and related pseudo-code from a binary file.

TODO: screenshot?

## Features

* Blazing fast, headless user experience courtesy of IDA Pro 9 and Binarly's idalib Rust bindings.
* Support for binary targets for any architecture implemented by IDA Pro's Hex-Rays decompiler.
* Decompilation feature based on the `decompile_to_file` API exported by [haruspex](https://github.com/0xdea/haruspex).
* Pseudo-code of each function that references a specific string is stored in a separate directory.

## Blog post

* <https://security.humanativaspa.it/streamlining-vulnerability-research-with-ida-pro-and-rust> (*coming soon*)

## See also

* <https://github.com/0xdea/rhabdomancer>
* <https://github.com/0xdea/haruspex>
* <https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib>
* <https://github.com/binarly-io/idalib>

## Installing

The easiest way to get the latest release is via [crates.io](https://crates.io/crates/augur):

1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
2. Download and extract the IDA SDK (see <https://docs.hex-rays.com/developer-guide>).
3. Install augur as follows:
    ```sh
    $ export IDASDKDIR=/path/to/idasdk90
    $ export IDADIR=/path/to/ida # if not set, the build script will check common locations
    $ cargo install augur
    ```

## Compiling

Alternatively, you can build from [source](https://github.com/0xdea/augur):

1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
2. Download and extract the IDA SDK (see <https://docs.hex-rays.com/developer-guide>).
3. Compile augur as follows:
    ```sh
    $ git clone https://github.com/0xdea/augur
    $ cd augur
    $ export IDASDKDIR=/path/to/idasdk90 # or edit .cargo/config.toml
    $ export IDADIR=/path/to/ida # if not set, the build script will check common locations
    $ cargo build --release
    ```

## Usage

1. Make sure IDA Pro is properly configured with a valid license.
2. Run augur as follows:
    ```sh
    $ augur <binary_file>
    ```
3. Find the extracted pseudo-code of each decompiled function in the `binary_file.str` directory, organized by string:
    ```sh
    $ vim <binary_file>.str
    $ code <binary_file>.str
    ```

## Tested with

* IDA Pro 9.0.241217 on macOS arm64 and Linux x64.

*Note: only the `unix` target family is currently supported, check [idalib](https://github.com/binarly-io/idalib)
documentation if you want to port it yourself to `windows` (or `wasm`).*

## Changelog

* [CHANGELOG.md](CHANGELOG.md)

## TODO

* Implement support for the `windows` target family.
* Allow users to choose to process string cross-references even if decompiler is unavailable.
