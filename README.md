mrt_parser
========

Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format ([RFC 6396](https://tools.ietf.org/html/rfc6396)) parser 
library for Rust.
Inspired by parser from [pyasn](https://github.com/hadiasghari/pyasn).

Currently, only `PEER_INDEX_TABLE`, `RIB_IPV4_UNICAST` and `RIB_IPV6_UNICAST` subtypes from `TABLE_DUMP_V2` type and `TABLE_DUMP` type  are supported.

[![Documentation](https://docs.rs/mrt_parser/badge.svg)](https://docs.rs/mrt_parser)
[![Build Status](https://travis-ci.com/JakubOnderka/mrt_parser.svg?branch=master)](https://travis-ci.com/JakubOnderka/mrt_parser)
[![Crates.io](https://img.shields.io/crates/v/mrt_parser.svg)](https://crates.io/crates/mrt_parser)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
mrt_parser = "0.5"
```

and this to your crate root:

```rust
extern crate mrt_parser;
```

Minimal required version of Rust compiler is 1.31 (because of 2018 edition). For older Rust versions, you can use
`mrt_parser` version 0.2. 

