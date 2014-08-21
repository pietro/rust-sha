// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::default::Default;

/// `Sha1State` computes a SHA-1 hash ove a stream of bytes.
pub struct Sha1State {
    state: [u32, ..5],
    count: uint,
    buffer: [u8, ..64]
}

macro_rules! u8tou32 (
    ($buf:expr, $i:expr) =>
    ($buf[$i+0] as u32 << 24|
     $buf[$i+1] as u32 << 16 |
     $buf[$i+2] as u32 <<  8 |
     $buf[$i+3] as u32);
)

macro_rules! hash2digest (
    ($hash_slice:expr) =>
        ([($hash_slice[0>>2] >> 8 * (3 - (0 & 0x03))) as u8,
          ($hash_slice[1>>2] >> 8 * (3 - (1 & 0x03))) as u8,
          ($hash_slice[2>>2] >> 8 * (3 - (2 & 0x03))) as u8,
          ($hash_slice[3>>2] >> 8 * (3 - (3 & 0x03))) as u8,
          ($hash_slice[4>>2] >> 8 * (3 - (4 & 0x03))) as u8,
          ($hash_slice[5>>2] >> 8 * (3 - (5 & 0x03))) as u8,
          ($hash_slice[6>>2] >> 8 * (3 - (6 & 0x03))) as u8,
          ($hash_slice[7>>2] >> 8 * (3 - (7 & 0x03))) as u8,
          ($hash_slice[8>>2] >> 8 * (3 - (8 & 0x03))) as u8,
          ($hash_slice[9>>2] >> 8 * (3 - (9 & 0x03))) as u8,
          ($hash_slice[10>>2] >> 8 * (3 - (10 & 0x03))) as u8,
          ($hash_slice[11>>2] >> 8 * (3 - (11 & 0x03))) as u8,
          ($hash_slice[12>>2] >> 8 * (3 - (12 & 0x03))) as u8,
          ($hash_slice[13>>2] >> 8 * (3 - (13 & 0x03))) as u8,
          ($hash_slice[14>>2] >> 8 * (3 - (14 & 0x03))) as u8,
          ($hash_slice[15>>2] >> 8 * (3 - (15 & 0x03))) as u8,
          ($hash_slice[16>>2] >> 8 * (3 - (16 & 0x03))) as u8,
          ($hash_slice[17>>2] >> 8 * (3 - (17 & 0x03))) as u8,
          ($hash_slice[18>>2] >> 8 * (3 - (18 & 0x03))) as u8,
          ($hash_slice[19>>2] >> 8 * (3 - (19 & 0x03))) as u8
         ];
     )
)

macro_rules! rotl (
    ($x:expr, $b:expr) =>
    (($x << $b) | ($x >> (32 - $b)))
)

 impl Sha1State {
     /// Create a `Sha1State` set to the inital hash value.
     #[inline]
     pub fn new() -> Sha1State {
         Sha1State { state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
                     count: 0,
                     buffer: [0u8, ..64]
         }
     }

     /// Reset the state back to the initial hash value.
     #[inline]
     pub fn reset(&mut self) {
         self.state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
         self.count = 0;
         self.buffer = [0u8, ..64];
     }

     /// Hash a 512-bit block.
     fn hash_block(&mut self) {
         let message_sched: &mut[u32, ..80] = &mut [0u32, ..80];
         let mut a = self.state[0];
         let mut b = self.state[1];
         let mut c = self.state[2];
         let mut d = self.state[3];
         let mut e = self.state[4];

         for t in range(0, 16) {
             message_sched[t] = u8tou32!(self.buffer, t * 4);
             let temp = rotl!(a, 5) + ((b & c) ^ (!b & d)) + e + 0x5a827999u32 + message_sched[t];
             e = d;
             d = c;
             c = rotl!(b, 30);
             b = a;
             a = temp;
         }

         for t in range(16, 20) {
             let ms_temp = rotl!(message_sched[t-3] ^ message_sched[t-8] ^ message_sched[t-14] ^ message_sched[t-16], 1);
             message_sched[t] = ms_temp;
             let temp = rotl!(a, 5) + ((b & c) ^ (!b & d)) + e + 0x5a827999 + message_sched[t];
             e = d;
             d = c;
             c = rotl!(b, 30);
             b = a;
             a = temp;
         }

         for t in range(20, 40) {
             let ms_temp = rotl!(message_sched[t-3] ^ message_sched[t-8] ^ message_sched[t-14] ^ message_sched[t-16], 1);
             message_sched[t] = ms_temp;
             let temp = rotl!(a, 5) + (b ^ c ^ d) + e + 0x6ed9eba1 + message_sched[t];
             e = d;
             d = c;
             c = rotl!(b, 30);
             b = a;
             a = temp;
         }

         for t in range(40, 60) {
             let ms_temp = rotl!(message_sched[t-3] ^ message_sched[t-8] ^ message_sched[t-14] ^ message_sched[t-16], 1);
             message_sched[t] = ms_temp;
             let temp = rotl!(a, 5) +  ((b & c) ^ (b & d) ^ (c & d)) + e + 0x8f1bbcdc + message_sched[t];
             e = d;
             d = c;
             c = rotl!(b, 30);
             b = a;
             a = temp;
         }

         for t in range(60, 80) {
             let ms_temp = rotl!(message_sched[t-3] ^ message_sched[t-8] ^ message_sched[t-14] ^ message_sched[t-16], 1);
             message_sched[t] = ms_temp;
             let temp = rotl!(a, 5) + (b ^ c ^ d) + e + 0xca62c1d6 + message_sched[t];
             e = d;
             d = c;
             c = rotl!(b, 30);
             b = a;
             a = temp;
         }
         self.state[0] += a;
         self.state[1] += b;
         self.state[2] += c;
         self.state[3] += d;
         self.state[4] += e;
     }

     /// Computes the 160-bit digest of the byte slice.
     pub fn hash(&mut self, message: &[u8]) -> [u8, ..20] {
         let bit_len: u64 = message.len() as u64 * 8;

         for i in range(0, message.len()) {
             self.buffer[self.count] = message[i];
             self.count += 1;

             if self.count == 64 {
                 self.count = 0;
                 self.hash_block();
             }
         }
         if self.count > 55  {
             self.buffer[self.count] = 0x80;
             self.count += 1;
             while self.count < 64 {
                 self.buffer[self.count] = 0;
                 self.count += 1;
             }
             self.count = 0;
             self.hash_block();
             while self.count < 56 {
                 self.buffer[self.count] = 0;
                 self.count += 1;
             }
         } else {
             self.buffer[self.count] = 0x80;
             self.count += 1;
             while self.count < 56 {
                 self.buffer[self.count] = 0;
                 self.count += 1;
             }
         }
         self.buffer[self.count] = (bit_len >> 56) as u8;
         self.buffer[self.count + 1] = (bit_len >> 48) as u8;
         self.buffer[self.count + 2] = (bit_len >> 40) as u8;
         self.buffer[self.count + 3] = (bit_len >> 32) as u8;
         self.buffer[self.count + 4] = (bit_len >> 24) as u8;
         self.buffer[self.count + 5] = (bit_len >> 16) as u8;
         self.buffer[self.count + 6] = (bit_len >> 8) as u8;
         self.buffer[self.count + 7] = bit_len as u8;
         self.count = 0;
         self.hash_block();

         hash2digest!(self.state)
     }
 }

impl Clone for Sha1State {
    #[inline]
    fn clone(&self) -> Sha1State {
        *self
    }
}

impl Default for Sha1State {
    #[inline]
    fn default() -> Sha1State {
        Sha1State::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha1State;

    #[test]
    fn test_sha1() {
        let mut sha1_state = Sha1State::new();
        let str1 = "abc".as_bytes();
        //let result = sha1_state.hash(str1);
        let expected = [0xA9u8, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D];
        assert!(sha1_state.hash(str1) == expected);

        sha1_state.reset();

        let str2: &[u8] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
        //    let result2 = sha1_state.hash(str2);
        let expected2 = [0x84u8, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1];
        assert!(sha1_state.hash(str2) == expected2);

        sha1_state.reset();

        let str3_vec = String::from_char(1000000, 'a').into_bytes();
        let str3 = str3_vec.as_slice();
        //  let result3 = sha1_state.hash(str3);
        let expected3 = [0x34u8, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E, 0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F];
        assert!(sha1_state.hash(str3) == expected3);

        sha1_state.reset();

        let str4 = "0123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567".as_bytes();
        let result4 = &sha1_state.hash(str4);
        let expected4 = [0xDEu8, 0xA3, 0x56, 0xA2, 0xCD, 0xDD, 0x90, 0xC7, 0xA7, 0xEC, 0xED, 0xC5, 0xEB, 0xB5, 0x63, 0x93, 0x4F, 0x46, 0x04, 0x52];
        assert!(*result4 == expected4);
    }
}
