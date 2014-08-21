//! SHA-1 and SHA-2 cryptographic hash functions

#![crate_name = "sha"]
#![comment = "SHA-1 and SHA-2 hash functions"]
#![license = "MIT/ASL2"]
#![crate_type = "lib"]

#![feature(macro_rules, default_type_params, phase, globs)]

#[phase(plugin, link)] extern crate log;
extern crate debug;

pub mod sha1;
