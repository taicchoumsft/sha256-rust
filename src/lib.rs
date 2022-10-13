use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

// https://en.wikipedia.org/wiki/SHA-2#Hash_standard
// https://blog.boot.dev/cryptography/how-sha-2-works-step-by-step-sha-256

#[derive(Debug)]
pub struct Sha2 {
    h: [u32; 8],
    k: [u32; 64],
    w: [u32; 64],
}

impl Default for Sha2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha2 {
    pub fn new() -> Self {
        //Initialize hash values:
        Self {
            //(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            //Initialize array of round constants:
            //(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
            k: [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
                0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
                0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
                0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
                0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
                0xc67178f2,
            ],
            //create a 64-entry message schedule array w[0..63] of 32-bit words
            w: [0; 64],
        }
    }

    pub fn sum(self, filename: &String) -> io::Result<String> {
        self.algo(filename)
    }

    fn algo(mut self, filepath: &String) -> io::Result<String> {
        // Create path to file
        let path = Path::new(filepath);

        // Open path in read-only
        let mut file = File::open(&path)?;

        // Break into 512-bit chunks - every element in the vector represents 1 byte
        let chunk_size: usize = 0x200 / 8;
        let mut total_size: usize = 0;
        let mut has_marked_1: bool = false;
        let mut has_seen_0: bool = false;
        let mut chunk = Vec::with_capacity(chunk_size);

        loop {
            chunk.clear();
            let n = file
                .by_ref()
                .take(chunk_size as u64)
                .read_to_end(&mut chunk)?;
            if has_seen_0 {
                break;
            }

            total_size += n * 8;

            //if n + 1 + 8 <= 512/8, we can fit the length to the end of array, otherwise we have to append size to next chunk
            if (n + 1 + 8) <= chunk_size {
                if !has_marked_1 {
                    chunk.push(0x80);
                }
                chunk.resize(chunk_size, 0);
                for i in 0..8 {
                    chunk[chunk_size - i - 1] = ((total_size >> (i * 8)) & 0xff) as u8;
                }
                has_seen_0 = true;
                has_marked_1 = true;
            } else if (n + 1) <= chunk_size {
                chunk.push(0x80);
                has_marked_1 = true;
            }
            chunk.resize(chunk_size, 0);

            // copy chunk into first 16 words w[0..15] of the message schedule array
            // copy every 4 segments in chunk into 1 32-bit word, since 1 segment is u8
            // also switch to big endian
            for i in 0..16 {
                self.w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
            }

            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
            for i in 16..64 {
                let s0 = u32::rotate_right(self.w[i - 15], 7)
                    ^ u32::rotate_right(self.w[i - 15], 18)
                    ^ (self.w[i - 15] >> 3);

                let s1 = u32::rotate_right(self.w[i - 2], 17)
                    ^ u32::rotate_right(self.w[i - 2], 19)
                    ^ (self.w[i - 2] >> 10);

		self.w[i] = self.w[i-16].wrapping_add(s0).wrapping_add(self.w[i-7]).wrapping_add(s1);
                //self.w[i] = (self.w[i - 16] + s0 + self.w[i - 7] + s1) % 2u32.pow(32);
            }

            self.compress();
        }

        let digest = self
            .h
            .iter()
            .map(|i| format!("{:x}", i))
            .collect::<String>();

        Ok(digest)
    }

    fn compress(&mut self) {
        // Initialize working variables to current hash value
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;

        // Compression function main loop
        for i in 0..64 {
            let s1 = u32::rotate_right(e, 6) ^ u32::rotate_right(e, 11) ^ u32::rotate_right(e, 25);

            let ch = (e & f) ^ (!e & g);

            //let temp1 = h + s1 + ch + self.k[i] + self.w[i];
	    let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(self.k[i]).wrapping_add(self.w[i]);

            let s0 = u32::rotate_right(a, 2) ^ u32::rotate_right(a, 13) ^ u32::rotate_right(a, 22);

            let maj = (a & b) ^ (a & c) ^ (b & c);

            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        //Add the compressed chunk to the current hash value:
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}
