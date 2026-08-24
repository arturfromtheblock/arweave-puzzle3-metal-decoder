#include <metal_stdlib>
using namespace metal;

// ============================================================================
// SHA-512 Implementation
// ============================================================================

constant ulong K[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

inline ulong rotr64(ulong x, uint n) {
    return (x >> n) | (x << (64 - n));
}

inline ulong ch(ulong x, ulong y, ulong z) {
    return (x & y) ^ (~x & z);
}

inline ulong maj(ulong x, ulong y, ulong z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline ulong sigma0(ulong x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

inline ulong sigma1(ulong x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

inline ulong gamma0(ulong x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

inline ulong gamma1(ulong x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

void sha512_transform(thread ulong* state, thread uchar* block) {
    ulong W[80];

    for (int i = 0; i < 16; i++) {
        W[i] = ((ulong)block[i*8] << 56) | ((ulong)block[i*8+1] << 48) |
               ((ulong)block[i*8+2] << 40) | ((ulong)block[i*8+3] << 32) |
               ((ulong)block[i*8+4] << 24) | ((ulong)block[i*8+5] << 16) |
               ((ulong)block[i*8+6] << 8) | ((ulong)block[i*8+7]);
    }

    for (int i = 16; i < 80; i++) {
        W[i] = gamma1(W[i-2]) + W[i-7] + gamma0(W[i-15]) + W[i-16];
    }

    ulong a = state[0], b = state[1], c = state[2], d = state[3];
    ulong e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 80; i++) {
        ulong t1 = h + sigma1(e) + ch(e, f, g) + K[i] + W[i];
        ulong t2 = sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha512(thread uchar* data, uint len, thread uchar* hash) {
    ulong state[8] = {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };

    uchar block[128];
    uint pos = 0;

    while (len - pos >= 128) {
        for (int i = 0; i < 128; i++) block[i] = data[pos + i];
        sha512_transform(state, block);
        pos += 128;
    }

    uint remainder = len - pos;
    for (uint i = 0; i < remainder; i++) {
        block[i] = data[pos + i];
    }
    block[remainder] = 0x80;

    if (remainder >= 112) {
        for (uint i = remainder + 1; i < 128; i++) block[i] = 0;
        sha512_transform(state, block);
        for (uint i = 0; i < 128; i++) block[i] = 0;
    } else {
        for (uint i = remainder + 1; i < 128; i++) block[i] = 0;
    }

    ulong bitlen = (ulong)len * 8;
    for (int i = 0; i < 8; i++) {
        block[127 - i] = (bitlen >> (i * 8)) & 0xFF;
    }

    sha512_transform(state, block);

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            hash[i*8 + j] = (state[i] >> (56 - j*8)) & 0xFF;
        }
    }
}

// ============================================================================
// MD5 Implementation
// ============================================================================

inline uint md5_f(uint x, uint y, uint z) { return (x & y) | (~x & z); }
inline uint md5_g(uint x, uint y, uint z) { return (x & z) | (y & ~z); }
inline uint md5_h(uint x, uint y, uint z) { return x ^ y ^ z; }
inline uint md5_i(uint x, uint y, uint z) { return y ^ (x | ~z); }

inline uint rotl(uint x, uint n) {
    return (x << n) | (x >> (32 - n));
}

// MD5 constants (global scope)
constant uint MD5_T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

constant int MD5_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

constant char HEX_CHARS[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
constant uchar SALTED_PREFIX[8] = {'S','a','l','t','e','d','_','_'};

void md5_transform(thread uint* state, thread uchar* block) {

    uint X[16];
    for (int i = 0; i < 16; i++) {
        X[i] = (uint)block[i*4] | ((uint)block[i*4+1] << 8) |
               ((uint)block[i*4+2] << 16) | ((uint)block[i*4+3] << 24);
    }

    uint a = state[0], b = state[1], c = state[2], d = state[3];

    for (int i = 0; i < 64; i++) {
        uint f, g;
        if (i < 16) {
            f = md5_f(b, c, d);
            g = i;
        } else if (i < 32) {
            f = md5_g(b, c, d);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = md5_h(b, c, d);
            g = (3 * i + 5) % 16;
        } else {
            f = md5_i(b, c, d);
            g = (7 * i) % 16;
        }

        uint temp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + MD5_T[i] + X[g], MD5_S[i]);
        a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

void md5(thread uchar* data, uint len, thread uchar* hash) {
    uint state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

    uchar block[64];
    uint pos = 0;

    while (len - pos >= 64) {
        for (int i = 0; i < 64; i++) block[i] = data[pos + i];
        md5_transform(state, block);
        pos += 64;
    }

    uint remainder = len - pos;
    for (uint i = 0; i < remainder; i++) {
        block[i] = data[pos + i];
    }
    block[remainder] = 0x80;

    if (remainder >= 56) {
        for (uint i = remainder + 1; i < 64; i++) block[i] = 0;
        md5_transform(state, block);
        for (uint i = 0; i < 64; i++) block[i] = 0;
    } else {
        for (uint i = remainder + 1; i < 64; i++) block[i] = 0;
    }

    ulong bitlen = (ulong)len * 8;
    for (int i = 0; i < 8; i++) {
        block[56 + i] = (bitlen >> (i * 8)) & 0xFF;
    }

    md5_transform(state, block);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            hash[i*4 + j] = (state[i] >> (j * 8)) & 0xFF;
        }
    }
}

// ============================================================================
// Rijndael-128 with variable key length (128 bytes = 1024 bits)
// ============================================================================

constant uchar SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

constant uchar INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

inline uchar xtime(uchar x) {
    return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
}

uchar gmul(uchar a, uchar b) {
    uchar p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi = (a & 0x80);
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

inline uint rot_word(uint w) {
    return (w << 8) | (w >> 24);
}

inline uint sub_word(uint w) {
    return ((uint)SBOX[(w >> 24) & 0xff] << 24) |
           ((uint)SBOX[(w >> 16) & 0xff] << 16) |
           ((uint)SBOX[(w >> 8) & 0xff] << 8) |
           ((uint)SBOX[w & 0xff]);
}

// Rijndael key expansion for 128-byte key (Nk=32, Nr=38)
void expand_key_128(thread uchar* key_bytes, thread uchar* round_keys) {
    const int Nk = 32;  // 128 bytes / 4 = 32 words
    const int Nr = 38;  // Nk + 6 = 38 rounds
    const int w_len = 4 * (Nr + 1);  // 156 words

    uint w[156];

    // Load initial key as BIG-ENDIAN words (wichtig!)
    for (int i = 0; i < Nk; i++) {
        w[i] = ((uint)key_bytes[i*4] << 24) | ((uint)key_bytes[i*4+1] << 16) |
               ((uint)key_bytes[i*4+2] << 8) | ((uint)key_bytes[i*4+3]);
    }

    // Rcon values
    uchar rcon_val = 1;
    uint rcon[40];
    rcon[0] = 0;
    for (int i = 1; i < 40; i++) {
        rcon[i] = (uint)rcon_val << 24;
        rcon_val = xtime(rcon_val);
    }

    // Generate key schedule
    for (int i = Nk; i < w_len; i++) {
        uint temp = w[i - 1];

        if (i % Nk == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            temp = sub_word(temp);
        }

        w[i] = w[i - Nk] ^ temp;
    }

    // Flatten to round keys bytes - COLUMN-MAJOR ORDER wie in Rust!
    for (int r = 0; r <= Nr; r++) {
        for (int c = 0; c < 4; c++) {
            uint word = w[r * 4 + c];
            int off = r * 16 + c * 4;
            round_keys[off + 0] = (word >> 24) & 0xFF;
            round_keys[off + 1] = (word >> 16) & 0xFF;
            round_keys[off + 2] = (word >> 8) & 0xFF;
            round_keys[off + 3] = word & 0xFF;
        }
    }
}

void inv_shift_rows(thread uchar* s) {
    uchar t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; uchar t2 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t; s[14] = t2;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

void inv_sub_bytes(thread uchar* s) {
    for (int i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
}

void add_round_key(thread uchar* s, thread uchar* round_keys, int round) {
    for (int i = 0; i < 16; i++) {
        s[i] ^= round_keys[round * 16 + i];
    }
}

void inv_mix_columns(thread uchar* s) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uchar a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
        s[i]   = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        s[i+1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        s[i+2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        s[i+3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

void decrypt_block(thread uchar* state, thread uchar* round_keys) {
    const int Nr = 38;

    // Initial round
    add_round_key(state, round_keys, Nr);

    // Main rounds
    for (int round = Nr - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_keys, round);
        inv_mix_columns(state);
    }

    // Final round
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_keys, 0);
}

// CBC decrypt with PKCS7 unpadding
bool cbc_decrypt(thread uchar* ciphertext, uint ct_len, thread uchar* key_bytes,
                 thread uchar* iv, thread uchar* output, thread uint* out_len) {
    if (ct_len % 16 != 0 || ct_len == 0) return false;

    // Expand key - round_keys = (Nr+1) * 16 = 39 * 16 = 624 bytes
    uchar round_keys[624];
    expand_key_128(key_bytes, round_keys);

    uchar prev_block[16];
    for (int i = 0; i < 16; i++) prev_block[i] = iv[i];

    uint blocks = ct_len / 16;
    uint pos = 0;

    for (uint b = 0; b < blocks; b++) {
        uchar state[16];
        uchar cipher_block[16];

        // Copy ciphertext block
        for (int i = 0; i < 16; i++) {
            cipher_block[i] = ciphertext[b * 16 + i];
            state[i] = cipher_block[i];
        }

        // Decrypt block
        decrypt_block(state, round_keys);

        // XOR with previous (CBC)
        for (int i = 0; i < 16; i++) {
            state[i] ^= prev_block[i];
            output[pos++] = state[i];
            prev_block[i] = cipher_block[i];
        }
    }

    // PKCS7 unpad
    if (pos == 0) return false;
    uchar pad = output[pos - 1];

    if (pad == 0 || pad > 16 || pad > pos) return false;

    // Verify padding
    for (uint i = pos - pad; i < pos; i++) {
        if (output[i] != pad) return false;
    }

    *out_len = pos - pad;
    return true;
}

// hex2a conversion - OPTIMIZED für 1024 Bytes
void hex2a(thread uchar* plaintext_bytes, uint plain_len, thread uchar* output, thread uint* out_len) {
    // plaintext_bytes sind die rohen Bytes nach Decrypt
    // Wir müssen diese zu Hex-String konvertieren, dann hex2a

    // 1. Bytes → Hex-String
    uchar hex_string[2048];  // Max: 1024 bytes → 2048 hex chars (angepasst)
    uint hex_len = 0;

    for (uint i = 0; i < plain_len && hex_len < 8192 - 1; i++) {
        uchar b = plaintext_bytes[i];
        hex_string[hex_len++] = HEX_CHARS[b >> 4];
        hex_string[hex_len++] = HEX_CHARS[b & 0x0f];
    }

    // 2. Hex-String → ASCII (hex2a)
    uint pos = 0;
    uint n = 0;

    while (n + 1 < hex_len && pos < 4096) {
        // Check for "00" terminator
        if (hex_string[n] == '0' && hex_string[n+1] == '0') {
            break;
        }

        // Parse two hex chars to byte
        uchar high = 0, low = 0;

        for (int j = 0; j < 16; j++) {
            if (hex_string[n] == HEX_CHARS[j]) high = j;
            if (hex_string[n+1] == HEX_CHARS[j]) low = j;
        }

        uchar byte_val = (high << 4) | low;
        output[pos++] = byte_val;
        n += 2;
    }

    *out_len = pos;
}

// Check if string contains RSA marker - OPTIMIZED
bool contains_rsa_marker(const thread uchar* d, uint len) {
    if (len < 12) return false;        // JSON braucht etwas Länge

    uint max_check = min(len - 3, 96u); // nur erste ~96 Bytes prüfen

    for (uint i = 0; i < max_check; i++) {
        if (d[i] == '"' && d[i+1] == 'k' && d[i+2] == 't' && d[i+3] == 'y' && d[i+4] == '"') {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Main GPU Kernel - OPTIMIZED Version
// ============================================================================
constant uint MAX_CT_LEN = 4096;
constant uint OUTPUT_MAX_LEN = 4096;

// Kernel 1: Nur Key-Derivation (SHA512 + EvpKDF)
kernel void derive_keys_batch(
    constant uchar* passphrases [[buffer(0)]],
    constant uint* pass_offsets [[buffer(1)]],
    constant uint* pass_lengths [[buffer(2)]],
    constant uchar* salt [[buffer(3)]],               // 8-Byte-Salt aus Ciphertext
    device uchar* derived_keys [[buffer(4)]],         // Ausgabe: batch_size * 144 Bytes (128 key + 16 iv)
    constant uint& batch_size [[buffer(5)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= batch_size) return;

    uint offset = pass_offsets[gid];
    uint len = pass_lengths[gid];
    if (len == 0 || len > 128) return;

    uchar passphrase[128];
    for (uint i = 0; i < len; i++) {
        passphrase[i] = passphrases[offset + i];
    }

    // SHA512 + 11512 Iterationen
    uchar hash[64];
    sha512(passphrase, len, hash);
    for (int iter = 0; iter < 11512; iter++) {
        sha512(hash, 64, hash);
    }

    // Zu Hex-String
    uchar pw_hex[128];
    for (int i = 0; i < 64; i++) {
        pw_hex[i*2]     = HEX_CHARS[hash[i] >> 4];
        pw_hex[i*2 + 1] = HEX_CHARS[hash[i] & 0x0f];
    }

    // EvpKDF (MD5, 10000 Iterationen)
    uchar derived[144] = {0};
    uint derived_pos = 0;
    uchar md5_block[16];
    bool first = true;

    while (derived_pos < 144) {
        uchar kdf_input[152];  // 16 + 128 + 8 = 152
        uint input_len = 0;

        if (!first) {
            for (int i = 0; i < 16; i++) kdf_input[input_len++] = md5_block[i];
        }
        for (int i = 0; i < 128; i++) kdf_input[input_len++] = pw_hex[i];
        for (int i = 0; i < 8; i++) kdf_input[input_len++] = salt[i];

        md5(kdf_input, input_len, md5_block);
        for (int iter = 1; iter < 10000; iter++) {
            md5(md5_block, 16, md5_block);
        }

        for (int i = 0; i < 16 && derived_pos < 144; i++) {
            derived[derived_pos++] = md5_block[i];
        }
        first = false;
    }

    // Speichern
    //uint base = gid * 144;
    //for (int i = 0; i < 144; i++) {
    //    derived_keys[base + i] = derived[i];
    //}
    ulong base = (ulong)gid * 144UL;
    for (int i = 0; i < 144; i++) {
        derived_keys[base + i] = derived[i];
    }
}

// Kernel 2: Nur Decrypt (Rijndael-128 CBC)
kernel void decrypt_batch(
    constant uchar* ciphertext [[buffer(0)]],      // Vollständiger Ciphertext-Buffer (inkl. "Salted__" + Salt + CT)
    constant uint& ct_len [[buffer(1)]],
    constant uchar* derived_keys [[buffer(2)]],    // batch_size * 144
    device uchar* plaintexts [[buffer(3)]],        // batch_size * MAX_CT_LEN
    device uint* plain_lengths [[buffer(4)]],
    constant uint& batch_size [[buffer(5)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= batch_size) return;

    //uint base = gid * 144;
    //uchar key[128], iv[16];
    //for (int i = 0; i < 128; i++) key[i] = derived_keys[base + i];
    //for (int i = 0; i < 16; i++) iv[i] = derived_keys[base + 128 + i];

    ulong base = (ulong)gid * 144UL;
    uchar key[128], iv[16];
    for (int i = 0; i < 128; i++) key[i] = derived_keys[base + i];
    for (int i = 0; i < 16; i++) iv[i] = derived_keys[base + 128 + i];

    // WICHTIG: Hier den Offset manuell addieren!
    constant uchar* ct_data = ciphertext + 16;
    uint data_len = ct_len - 16;

    if (data_len > MAX_CT_LEN || data_len % 16 != 0) {
        plain_lengths[gid] = 0;
        return;
    }

    uchar ct_copy[MAX_CT_LEN];
    for (uint i = 0; i < data_len; i++) {
        ct_copy[i] = ct_data[i];
    }

    uchar plaintext[MAX_CT_LEN];
    uint plain_len = 0;

    if (cbc_decrypt(ct_copy, data_len, key, iv, plaintext, &plain_len)) {
        //uint out_base = gid * MAX_CT_LEN;
        //for (uint i = 0; i < plain_len; i++) {
        //    plaintexts[out_base + i] = plaintext[i];
        //}
        ulong out_base = (ulong)gid * MAX_CT_LEN;
        for (uint i = 0; i < plain_len; i++) {
            plaintexts[out_base + i] = plaintext[i];
        }
        plain_lengths[gid] = plain_len;
    } else {
        plain_lengths[gid] = 0;
    }
}

// Kernel 3: Post-Processing (hex2a + Marker-Check)
kernel void postprocess_batch(
    constant uchar* plaintexts [[buffer(0)]],
    constant uint* plain_lengths [[buffer(1)]],
    device uint* results [[buffer(2)]],
    device uchar* output_data [[buffer(3)]],
    device uint* output_len [[buffer(4)]],
    constant uint& batch_size [[buffer(5)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= batch_size) return;

    uint plain_len = plain_lengths[gid];
    if (plain_len == 0) return;

    // CRITICAL FIX: Use ulong for ALL offset calculations!
    ulong base = (ulong)gid * (ulong)MAX_CT_LEN;  // Explicit cast BOTH operands!

    uchar plaintext[MAX_CT_LEN];
    for (uint i = 0; i < plain_len; i++) {
        plaintext[i] = plaintexts[base + i];
    }

    uchar decoded[OUTPUT_MAX_LEN];
    uint decoded_len = 0;
    hex2a(plaintext, plain_len, decoded, &decoded_len);

    if (contains_rsa_marker(decoded, decoded_len)) {
        results[gid] = 1;

        uint copy_len = min(decoded_len, OUTPUT_MAX_LEN);

        // CRITICAL FIX: Use ulong for output offset too!
        ulong out_base = (ulong)gid * (ulong)OUTPUT_MAX_LEN;

        for (uint i = 0; i < copy_len; i++) {
            output_data[out_base + i] = decoded[i];
        }
        output_len[gid] = decoded_len;
    }
}
