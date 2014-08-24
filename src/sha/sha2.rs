// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

macro_rules! sha256_SIGMA0 (
    ($x:expr) =>
    ((rotr32!($x, 2) ^ rotr32!($x, 13) ^ rotr32!($x, 22)))
)

macro_rules! sha256_SIGMA1 (
    ($x:expr) =>
    ((rotr32!($x, 6) ^ rotr32!($x, 11) ^ rotr32!($x, 25)))
)

macro_rules! sha256_sigma0 (
    ($x:expr) =>
    ((rotr32!($x, 7) ^ rotr32!($x, 18) ^ shr!($x, 3)))
)

macro_rules! sha256_sigma1 (
    ($x:expr) =>
    ((rotr32!($x, 17) ^ rotr32!($x, 19) ^ shr!($x, 10)))
)

macro_rules! sha512_SIGMA0 (
    ($x:expr) =>
    ((rotr64!($x, 28) ^ rotr64!($x, 34) ^ rotr64!($x, 39)))
)

macro_rules! sha512_SIGMA1 (
    ($x:expr) =>
    ((rotr64!($x, 14) ^ rotr64!($x, 18) ^ rotr64!($x, 41)))
)

macro_rules! sha512_sigma0 (
    ($x:expr) =>
    ((rotr64!($x, 1) ^ rotr64!($x, 8) ^ shr!($x, 7)))
)

macro_rules! sha512_sigma1 (
    ($x:expr) =>
    ((rotr64!($x, 19) ^ rotr64!($x, 61) ^ shr!($x, 6)))
)

static SHA256K: [u32, ..64] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                               0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                               0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                               0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                               0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                               0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                               0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                               0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

static SHA512K: [u64, ..80] = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                               0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                               0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                               0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                               0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                               0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                               0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                               0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                               0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                               0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                               0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                               0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                               0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                               0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                               0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                               0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                               0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                               0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                               0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                               0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];

/// `Sha224State` computes a SHA-224 hash ove a stream of bytes.
pub struct Sha224State {
    state: [u32, ..8],
    count: uint,
    buffer: [u8, ..64]
}

impl Sha224State {
    /// Create a `Sha224State` set to the inital hash value.
     #[inline]
    pub fn new() -> Sha224State {
        Sha224State { state: [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                              0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4],
                      count: 0,
                      buffer: [0u8, ..64]
        }
    }

    /// Reset the state back to the initial hash value.
    #[inline]
    pub fn reset(&mut self) {
        self.state = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                      0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
        self.count = 0;
        self.buffer = [0u8, ..64];
    }
}

/// `Sha256State` computes a SHA-256 hash ove a stream of bytes.
pub struct Sha256State {
    state: [u32, ..8],
    count: uint,
    buffer: [u8, ..64]
}

impl Sha256State {
    /// Create a `Sha256State` set to the inital hash value.
     #[inline]
    pub fn new() -> Sha256State {
        Sha256State { state: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
                      count: 0,
                      buffer: [0u8, ..64]
        }
    }

    /// Reset the state back to the initial hash value.
    #[inline]
    pub fn reset(&mut self) {
        self.state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        self.count = 0;
        self.buffer = [0u8, ..64];
    }

    /// Hash a 512-bit block.
    fn hash_block(&mut self) {
        let message_sched: &mut[u32, ..64] = &mut [0u32, ..64];
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for t in range(0, 16) {
            message_sched[t] = u8tou32!(self.buffer, t * 4);
            let temp1 = h + sha256_SIGMA1!(e) + ch!(e, f, g) + SHA256K[t] + message_sched[t];
            let temp2 = sha256_SIGMA0!(a) + maj!(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        for t in range(16, 64) {
            message_sched[t] = sha256_sigma1!(message_sched[t - 2]) + message_sched[t - 7] + sha256_sigma0!(message_sched[t - 15]) + message_sched[t - 16];
            let temp1 = h + sha256_SIGMA1!(e) + ch!(e, f, g) + SHA256K[t] + message_sched[t];
            let temp2 = sha256_SIGMA0!(a) + maj!(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;
        self.state[4] += e;
        self.state[5] += f;
        self.state[6] += g;
        self.state[7] += h;
    }

    /// Computes the 256-bit digest of the byte slice.
    pub fn hash(&mut self, message: &[u8]) -> [u8, ..32] {
        let bit_len: u64 = message.len() as u64 * 8;

        for i in range(0, message.len()) {
            self.buffer[self.count] = message[i];
            self.count += 1;

            if self.count == 64 {
                self.count = 0;
                self.hash_block();
            }
        }
        if self.count < 56 {
            self.buffer[self.count] = 0x80;
            self.count += 1;
	    while self.count < 56 {
                self.buffer[self.count] = 0x00;
                self.count += 1;
            }
        } else {
                self.buffer[self.count] = 0x80;
                self.count += 1;
	    while self.count < 64 {
                self.buffer[self.count] = 0x00;
                self.count += 1;
            }
            self.count = 0;
            self.hash_block();
	    while self.count < 56 {
                self.buffer[self.count] = 0x00;
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

        let &mut digest: &[u8, ..32] = &mut [0u8, ..32];
        for i in range(0, 8) {
            digest[i * 4]      = (self.state[i] >> 24) as u8;
	    digest[i * 4 + 1] = (self.state[i] >> 16) as u8;
	    digest[i * 4 + 2] = (self.state[i] >> 8) as u8;
	    digest[i * 4 + 3] =  self.state[i] as u8;
        }
        digest
    }

}

/// `Sha384State` computes a SHA-384 hash ove a stream of bytes.
pub struct Sha384State {
    state: [u64, ..8],
    count: uint,
    buffer: [u8, ..64]
}

impl Sha384State {
    /// Create a `Sha384State` set to the inital hash value.
     #[inline]
    pub fn new() -> Sha384State {
        Sha384State { state: [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
                              0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4],
                      count: 0,
                      buffer: [0u8, ..64]
        }
    }
}

/// `Sha512State` computes a SHA-512 hash ove a stream of bytes.
pub struct Sha512State {
    state: [u64, ..8],
    count: uint,
    buffer: [u8, ..128]
}

impl Sha512State {
    /// Create a `Sha512State` set to the inital hash value.
     #[inline]
    pub fn new() -> Sha512State {
        Sha512State { state: [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                              0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179],
                      count: 0,
                      buffer: [0u8, ..128]
        }
    }

    /// Reset the state back to the initial hash value.
    #[inline]
    pub fn reset(&mut self) {
        self.state = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                      0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];
        self.count = 0;
        self.buffer = [0u8, ..128];
    }

    /// Hash a 1024-bit block.
    fn hash_block(&mut self) {
        let message_sched: &mut[u64, ..80] = &mut [0u64, ..80];
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for t in range(0, 16) {
            message_sched[t] = u8tou64!(self.buffer, t * 8);
            let temp1 = h + sha512_SIGMA1!(e) + ch!(e, f, g) + SHA512K[t] + message_sched[t];
            let temp2 = sha512_SIGMA0!(a) + maj!(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        for t in range(16, 80) {
            message_sched[t] = sha512_sigma1!(message_sched[t-2]) + message_sched[t -7] + sha512_sigma0!(message_sched[t -15]) + message_sched[t -16];
            let temp1 = h + sha512_SIGMA1!(e) + ch!(e, f, g) + SHA512K[t] + message_sched[t];
            let temp2 = sha512_SIGMA0!(a) + maj!(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;
        self.state[4] += e;
        self.state[5] += f;
        self.state[6] += g;
        self.state[7] += h;
    }

    /// Computes the 512-bit digest of the byte slice.
    pub fn hash(&mut self, message: &[u8]) -> [u8, ..64] {
        let bit_len: u64 = message.len() as u64 * 8;

        for i in range(0, message.len()) {
            self.buffer[self.count] = message[i];
            self.count += 1;

            if self.count == 128 {
                self.count = 0;
                self.hash_block();
            }
        }
        if self.count > 111 {
            self.buffer[self.count] = 0x80;
            self.count += 1;
            while self.count < 128 {
                self.buffer[self.count] = 0;
                self.count += 1;
            }
            self.count = 0;
            self.hash_block();
            while self.count < 112 {
                self.buffer[self.count] = 0;
                self.count += 1;
            }
        } else {
            self.buffer[self.count] = 0x80;
            self.count += 1;
            while self.count < 120 {
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

        let &mut digest: &[u8, ..64] = &mut [0u8, ..64];
        for i in range(0, 8) {
            digest[i * 8]     = (self.state[i] >> 56) as u8;
	    digest[i * 8 + 1] = (self.state[i] >> 48) as u8;
	    digest[i * 8 + 2] = (self.state[i] >> 40) as u8;
	    digest[i * 8 + 3] = (self.state[i] >> 32) as u8;
	    digest[i * 8 + 4] = (self.state[i] >> 24) as u8;
	    digest[i * 8 + 5] = (self.state[i] >> 16) as u8;
	    digest[i * 8 + 6] = (self.state[i] >> 8) as u8;
	    digest[i * 8 + 7] = self.state[i] as u8;
        }
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::Sha256State;
    use super::Sha512State;

    #[test]
    fn test_sha256() {
        let mut sha256_state = Sha256State::new();
        let str1 = "abc".as_bytes();
        let expected: [u8, ..32] = [0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD];
        assert!(sha256_state.hash(str1) == expected);

        sha256_state.reset();

        let str2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
        let expected2: [u8, ..32] = [0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1];
        assert!(sha256_state.hash(str2) == expected2);
    }

    #[test]
    fn test_sha512() {
        let mut sha512_state = Sha512State::new();
        let str1 = "abc".as_bytes();
        let expected: [u8, ..64] = [0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
                                    0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2, 0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
                                    0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8, 0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
                                    0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E, 0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F];

        assert!(sha512_state.hash(str1) == expected);

        sha512_state.reset();

//        let str2 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
//        let expected2: [u8, ..64] = [0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA, 0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
//                                     0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1, 0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
//                                     0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4, 0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
//                                     0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54, 0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09];
//        assert!(sha512_state.hash(str2) == expected2);
    }

}
