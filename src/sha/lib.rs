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

#![feature(macro_rules, default_type_params, phase)]

#[phase(plugin, link)] extern crate log;
extern crate debug;

macro_rules! rotl (
    ($x:expr, $n:expr, $w:expr) =>
    (($x << $n) | ($x >> ($w - $n)))
)

macro_rules! rotl32 (
    ($x:expr, $n:expr) =>
    (rotl!($x, $n, 32))
)

macro_rules! rotl64 (
    ($x:expr, $n:expr) =>
    (rotl!($x, $n, 64))
)

macro_rules! rotr (
    ($x:expr, $n:expr, $w:expr) =>
    (($x >> $n) | ($x << ($w - $n)))
)

macro_rules! rotr32 (
    ($x:expr, $n:expr) =>
    (rotr!($x, $n, 32))

)

macro_rules! rotr64 (
    ($x:expr, $n:expr) =>
    (rotr!($x, $n, 64))
)

macro_rules! shr (
    ($x:expr, $n:expr) =>
    (($x >> $n))
)

macro_rules! ch (
    ($x:expr, $y:expr, $z:expr) =>
    ((($x & $y) ^ (!$x & $z)))
)

macro_rules! parity (
    ($x:expr, $y:expr, $z:expr) =>
    (($x ^ $y ^ $z))
)

macro_rules! maj (
    ($x:expr, $y:expr, $z:expr) =>
    ((($x & $y) ^ ($x & $z) ^ ($y & $z)))
)

macro_rules! u8tou32 (
    ($buf:expr, $i:expr) =>
    ($buf[$i+0] as u32 << 24|
     $buf[$i+1] as u32 << 16 |
     $buf[$i+2] as u32 <<  8 |
     $buf[$i+3] as u32);
)

macro_rules! u8tou64 (
    ($buf:expr, $i:expr) =>
    ($buf[$i] as u64 << 56 |
     $buf[$i+1] as u64 << 48 |
     $buf[$i+2] as u64 << 40 |
     $buf[$i+3] as u64 << 32 |
     $buf[$i+4] as u64 << 24 |
     $buf[$i+5] as u64 << 16 |
     $buf[$i+6] as u64 <<  8 |
     $buf[$i+7] as u64);
)

pub mod sha1;
pub mod sha2;
