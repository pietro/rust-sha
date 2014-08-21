// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! SHA-1 and SHA-2 cryptographic hash functions

#![crate_name = "sha"]
#![comment = "SHA-1 and SHA-2 hash functions"]
#![license = "MIT/ASL2"]
#![crate_type = "lib"]

#![feature(macro_rules, default_type_params, phase, globs)]

#[phase(plugin, link)] extern crate log;
extern crate debug;

pub mod sha1;
