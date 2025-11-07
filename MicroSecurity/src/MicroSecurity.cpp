#include "MicroSecurity.hpp"
#include <cstring>
#include <array>

namespace microsec {

// --- small SHA256 implementation ---

namespace {

inline uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t K256[64] = {
  0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
  0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
  0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
  0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
  0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
  0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
  0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
  0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

void sha256_internal(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };

    size_t fullBlocks = len / 64;
    size_t rem = len % 64;
    const uint8_t* p = data;

    auto process_block = [&](const uint8_t* block) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t)block[i*4] << 24 | (uint32_t)block[i*4+1] << 16 | (uint32_t)block[i*4+2] << 8 | (uint32_t)block[i*4+3];
        }
        for (int t = 16; t < 64; ++t) {
            uint32_t s0 = rotr(w[t-15],7) ^ rotr(w[t-15],18) ^ (w[t-15] >> 3);
            uint32_t s1 = rotr(w[t-2],17) ^ rotr(w[t-2],19) ^ (w[t-2] >> 10);
            w[t] = w[t-16] + s0 + w[t-7] + s1;
        }
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int t = 0; t < 64; ++t) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + K256[t] + w[t];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    };

    for (size_t i = 0; i < fullBlocks; ++i) {
        process_block(p + i*64);
    }

    // remainder + padding
    uint8_t last[128];
    memset(last,0,128);
    if (rem) memcpy(last, p + fullBlocks*64, rem);
    last[rem] = 0x80;
    uint64_t bitLen = (uint64_t)len * 8;
    // put length in last 8 bytes big-endian after padding
    // if rem >= 56 -> two blocks
    if (rem >= 56) {
        // write length at last+120
        last[120] = (uint8_t)(bitLen >> 56);
        last[121] = (uint8_t)(bitLen >> 48);
        last[122] = (uint8_t)(bitLen >> 40);
        last[123] = (uint8_t)(bitLen >> 32);
        last[124] = (uint8_t)(bitLen >> 24);
        last[125] = (uint8_t)(bitLen >> 16);
        last[126] = (uint8_t)(bitLen >> 8);
        last[127] = (uint8_t)(bitLen);
        process_block(last);
        process_block(last + 64);
    } else {
        last[56] = (uint8_t)(bitLen >> 56);
        last[57] = (uint8_t)(bitLen >> 48);
        last[58] = (uint8_t)(bitLen >> 40);
        last[59] = (uint8_t)(bitLen >> 32);
        last[60] = (uint8_t)(bitLen >> 24);
        last[61] = (uint8_t)(bitLen >> 16);
        last[62] = (uint8_t)(bitLen >> 8);
        last[63] = (uint8_t)(bitLen);
        process_block(last);
    }

    for (int i = 0; i < 8; ++i) {
        out[i*4] = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

} // anonymous

// --- class implementation ---

MicroSecurity_Obj::MicroSecurity_Obj(const std::vector<uint8_t>& key) : m_key(key) {}
MicroSecurity_Obj::~MicroSecurity_Obj() {}

void MicroSecurity_Obj::setKey(const std::vector<uint8_t>& key) { m_key = key; }
const std::vector<uint8_t>& MicroSecurity_Obj::getKey() const { return m_key; }

void MicroSecurity_Obj::sha256(const uint8_t* data, size_t len, uint8_t out32[32]) {
    sha256_internal(data, len, out32);
}

void MicroSecurity_Obj::hmac_sha256(const uint8_t* key, size_t keylen,
                                   const uint8_t* msg, size_t msglen,
                                   uint8_t out32[32]) {
    uint8_t k0[64];
    memset(k0, 0, 64);
    if (keylen > 64) {
        // key = SHA256(key)
        uint8_t tk[32];
        sha256_internal(key, keylen, tk);
        memcpy(k0, tk, 32);
    } else {
        memcpy(k0, key, keylen);
    }
    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }

    // inner hash
    uint8_t inner[32];
    // ipad || msg
    uint8_t *tmp = nullptr;
    // perform: SHA256(ipad || msg)
    // We'll call sha256_internal twice: one for ipad+msg
    // concat ipad and msg into buffer if small, else call sha sequentially
    // Since sha256_internal expects whole buffer, use a simple approach: allocate
    std::vector<uint8_t> ibuf(64 + msglen);
    memcpy(ibuf.data(), ipad, 64);
    if (msglen) memcpy(ibuf.data() + 64, msg, msglen);
    sha256_internal(ibuf.data(), ibuf.size(), inner);

    // outer
    std::vector<uint8_t> obuf(64 + 32);
    memcpy(obuf.data(), opad, 64);
    memcpy(obuf.data() + 64, inner, 32);
    sha256_internal(obuf.data(), obuf.size(), out32);
}

bool MicroSecurity_Obj::computeHMACTrunc(const uint8_t* seed, size_t seedLen,
                                         uint8_t* out, size_t outTrunc) const
{
    if (!seed || !out || outTrunc == 0 || outTrunc > 32) return false;
    if (m_key.empty()) return false;
    uint8_t mac[32];
    hmac_sha256(m_key.data(), m_key.size(), seed, seedLen, mac);
    memcpy(out, mac, outTrunc);
    return true;
}

bool MicroSecurity_Obj::computeSHA256ConcatTrunc(const uint8_t* seed, size_t seedLen,
                                                 uint8_t* out, size_t outTrunc,
                                                 const std::vector<uint8_t>* extraSecret) const
{
    if (!seed || !out || outTrunc == 0 || outTrunc > 32) return false;
    const uint8_t* secretPtr = nullptr;
    size_t secretLen = 0;
    if (extraSecret && !extraSecret->empty()) {
        secretPtr = extraSecret->data();
        secretLen = extraSecret->size();
    } else if (!m_key.empty()) {
        secretPtr = m_key.data();
        secretLen = m_key.size();
    } else return false;

    // concat seed || secret
    std::vector<uint8_t> buf(seedLen + secretLen);
    memcpy(buf.data(), seed, seedLen);
    memcpy(buf.data() + seedLen, secretPtr, secretLen);

    uint8_t hv[32];
    sha256_internal(buf.data(), buf.size(), hv);
    memcpy(out, hv, outTrunc);
    return true;
}

} // namespace microsec