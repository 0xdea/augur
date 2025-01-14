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
* Pseudo-code of each function that references a specific string is stored in a separate directory.

## Blog post:

* <https://security.humanativaspa.it/streamlining-vulnerability-research-with-ida-pro-and-rust> (*coming soon*)

## See also

* <https://github.com/0xdea/rhabdomancer>
* <https://github.com/0xdea/haruspex>
* <https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib>
* <https://github.com/binarly-io/idalib>

## Installing

The easiest way to get the latest release is via [crates.io](https://crates.io/crates/augur):

```sh
TODO
```

## Compiling

Alternatively, you can build from [source](https://github.com/0xdea/augur):

```sh
TODO
```

## Usage

```sh
TODO
```

## Examples

TODO:

```sh
TODO
```

TODO:

```sh
TODO
```

## Tested with

* IDA Pro 9.0.241217 on macOS arm64 and Linux x64.

*Note: not tested on Windows, check [idalib](https://github.com/binarly-io/idalib) documentation if you want to port it
yourself.*

## Changelog

* [CHANGELOG.md](CHANGELOG.md)

## TODO

* TODO
