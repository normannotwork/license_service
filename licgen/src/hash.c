#include "common.h"
#include "hash.h"
#include <string.h>
#include <stdint.h>

/**  Источники:
 *   - openssl/include/openssl/sha.h
 *   - openssl/crypto/sha/sha512.c
 */

#define SHA_LBLOCK      16
#define SHA512_CBLOCK   (SHA_LBLOCK*8)
#define SHA224_DIGEST_LENGTH    28
#define SHA256_DIGEST_LENGTH    32
#define SHA384_DIGEST_LENGTH    48
#define SHA512_DIGEST_LENGTH    HASH_LEN

typedef struct{
    uint64_t h[8];
    uint64_t Nl, Nh;
    union {
        uint64_t d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} sha512_ctx;

static const uint64_t K512[80] = {
    U64(0x428a2f98d728ae22), U64(0x7137449123ef65cd),
    U64(0xb5c0fbcfec4d3b2f), U64(0xe9b5dba58189dbbc),
    U64(0x3956c25bf348b538), U64(0x59f111f1b605d019),
    U64(0x923f82a4af194f9b), U64(0xab1c5ed5da6d8118),
    U64(0xd807aa98a3030242), U64(0x12835b0145706fbe),
    U64(0x243185be4ee4b28c), U64(0x550c7dc3d5ffb4e2),
    U64(0x72be5d74f27b896f), U64(0x80deb1fe3b1696b1),
    U64(0x9bdc06a725c71235), U64(0xc19bf174cf692694),
    U64(0xe49b69c19ef14ad2), U64(0xefbe4786384f25e3),
    U64(0x0fc19dc68b8cd5b5), U64(0x240ca1cc77ac9c65),
    U64(0x2de92c6f592b0275), U64(0x4a7484aa6ea6e483),
    U64(0x5cb0a9dcbd41fbd4), U64(0x76f988da831153b5),
    U64(0x983e5152ee66dfab), U64(0xa831c66d2db43210),
    U64(0xb00327c898fb213f), U64(0xbf597fc7beef0ee4),
    U64(0xc6e00bf33da88fc2), U64(0xd5a79147930aa725),
    U64(0x06ca6351e003826f), U64(0x142929670a0e6e70),
    U64(0x27b70a8546d22ffc), U64(0x2e1b21385c26c926),
    U64(0x4d2c6dfc5ac42aed), U64(0x53380d139d95b3df),
    U64(0x650a73548baf63de), U64(0x766a0abb3c77b2a8),
    U64(0x81c2c92e47edaee6), U64(0x92722c851482353b),
    U64(0xa2bfe8a14cf10364), U64(0xa81a664bbc423001),
    U64(0xc24b8b70d0f89791), U64(0xc76c51a30654be30),
    U64(0xd192e819d6ef5218), U64(0xd69906245565a910),
    U64(0xf40e35855771202a), U64(0x106aa07032bbd1b8),
    U64(0x19a4c116b8d2d0c8), U64(0x1e376c085141ab53),
    U64(0x2748774cdf8eeb99), U64(0x34b0bcb5e19b48a8),
    U64(0x391c0cb3c5c95a63), U64(0x4ed8aa4ae3418acb),
    U64(0x5b9cca4f7763e373), U64(0x682e6ff3d6b2b8a3),
    U64(0x748f82ee5defb2fc), U64(0x78a5636f43172f60),
    U64(0x84c87814a1f0ab72), U64(0x8cc702081a6439ec),
    U64(0x90befffa23631e28), U64(0xa4506cebde82bde9),
    U64(0xbef9a3f7b2c67915), U64(0xc67178f2e372532b),
    U64(0xca273eceea26619c), U64(0xd186b8c721c0c207),
    U64(0xeada7dd6cde0eb1e), U64(0xf57d4f7fee6ed178),
    U64(0x06f067aa72176fba), U64(0x0a637dc5a2c898a6),
    U64(0x113f9804bef90dae), U64(0x1b710b35131c471b),
    U64(0x28db77f523047d84), U64(0x32caab7b40c72493),
    U64(0x3c9ebe0a15c9bebc), U64(0x431d67c49c100d4c),
    U64(0x4cc5d4becb3e42b6), U64(0x597f299cfc657e2a),
    U64(0x5fcb6fab3ad6faec), U64(0x6c44198c4a475817)
};

// циклич. сдвиг вправо
#define ROTR(x,s)       (((x)>>s) | (x)<<(64-s))
#define Sigma0(x)       (ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
#define Sigma1(x)       (ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41))
#define sigma0(x)       (ROTR((x),1)  ^ ROTR((x),8)  ^ ((x)>>7))
#define sigma1(x)       (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))
#define Ch(x,y,z)       (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROUND_00_15(i,a,b,c,d,e,f,g,h)        do {    \
        T1 += h + Sigma1(e) + Ch(e,f,g) + K512[i];      \
        h = Sigma0(a) + Maj(a,b,c);                     \
        d += T1;        h += T1;                        } while (0)

#define ROUND_16_80(i,j,a,b,c,d,e,f,g,h,X)    do {    \
        s0 = X[(j+1)&0x0f];     s0 = sigma0(s0);        \
        s1 = X[(j+14)&0x0f];    s1 = sigma1(s1);        \
        T1 = X[(j)&0x0f] += s0 + s1 + X[(j+9)&0x0f];    \
        ROUND_00_15(i+j,a,b,c,d,e,f,g,h);               } while (0)

int initSHA512(sha512_ctx *ctx)
{
  ctx->h[0] = U64(0x6a09e667f3bcc908);
  ctx->h[1] = U64(0xbb67ae8584caa73b);
  ctx->h[2] = U64(0x3c6ef372fe94f82b);
  ctx->h[3] = U64(0xa54ff53a5f1d36f1);
  ctx->h[4] = U64(0x510e527fade682d1);
  ctx->h[5] = U64(0x9b05688c2b3e6c1f);
  ctx->h[6] = U64(0x1f83d9abfb41bd6b);
  ctx->h[7] = U64(0x5be0cd19137e2179);

  ctx->Nl = 0;
  ctx->Nh = 0;
  ctx->num = 0;
  ctx->md_len = SHA512_DIGEST_LENGTH;
  return 1;
}

uint64_t swapBytesQ(uint64_t in){
  uint64_t out = 0;

  out |= in >> 56 & 0xff;
  out |= (in >> 48 & 0xff) << 8;
  out |= (in >> 40 & 0xff) << 16;
  out |= (in >> 32 & 0xff) << 24;
  out |= (in >> 24 & 0xff) << 32;
  out |= (in >> 16 & 0xff) << 40;
  out |= (in >> 8 & 0xff) << 48;
  out |= (in & 0xff) << 56;

  return out;
}

static void sha512_block_data_order(sha512_ctx *ctx, const void *in,
                                    size_t num)
{
  const uint64_t *W = in;
  uint64_t a, b, c, d, e, f, g, h, s0, s1, T1;
  uint64_t X[16];
  int i;

  while (num--) {

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

#ifdef B_ENDIAN
    T1 = X[0] = W[0];
    ROUND_00_15(0, a, b, c, d, e, f, g, h);
    T1 = X[1] = W[1];
    ROUND_00_15(1, h, a, b, c, d, e, f, g);
    T1 = X[2] = W[2];
    ROUND_00_15(2, g, h, a, b, c, d, e, f);
    T1 = X[3] = W[3];
    ROUND_00_15(3, f, g, h, a, b, c, d, e);
    T1 = X[4] = W[4];
    ROUND_00_15(4, e, f, g, h, a, b, c, d);
    T1 = X[5] = W[5];
    ROUND_00_15(5, d, e, f, g, h, a, b, c);
    T1 = X[6] = W[6];
    ROUND_00_15(6, c, d, e, f, g, h, a, b);
    T1 = X[7] = W[7];
    ROUND_00_15(7, b, c, d, e, f, g, h, a);
    T1 = X[8] = W[8];
    ROUND_00_15(8, a, b, c, d, e, f, g, h);
    T1 = X[9] = W[9];
    ROUND_00_15(9, h, a, b, c, d, e, f, g);
    T1 = X[10] = W[10];
    ROUND_00_15(10, g, h, a, b, c, d, e, f);
    T1 = X[11] = W[11];
    ROUND_00_15(11, f, g, h, a, b, c, d, e);
    T1 = X[12] = W[12];
    ROUND_00_15(12, e, f, g, h, a, b, c, d);
    T1 = X[13] = W[13];
    ROUND_00_15(13, d, e, f, g, h, a, b, c);
    T1 = X[14] = W[14];
    ROUND_00_15(14, c, d, e, f, g, h, a, b);
    T1 = X[15] = W[15];
    ROUND_00_15(15, b, c, d, e, f, g, h, a);
#else
    T1 = X[0] = swapBytesQ(W[0]);
    ROUND_00_15(0, a, b, c, d, e, f, g, h);
    T1 = X[1] = swapBytesQ(W[1]);
    ROUND_00_15(1, h, a, b, c, d, e, f, g);
    T1 = X[2] = swapBytesQ(W[2]);
    ROUND_00_15(2, g, h, a, b, c, d, e, f);
    T1 = X[3] = swapBytesQ(W[3]);
    ROUND_00_15(3, f, g, h, a, b, c, d, e);
    T1 = X[4] = swapBytesQ(W[4]);
    ROUND_00_15(4, e, f, g, h, a, b, c, d);
    T1 = X[5] = swapBytesQ(W[5]);
    ROUND_00_15(5, d, e, f, g, h, a, b, c);
    T1 = X[6] = swapBytesQ(W[6]);
    ROUND_00_15(6, c, d, e, f, g, h, a, b);
    T1 = X[7] = swapBytesQ(W[7]);
    ROUND_00_15(7, b, c, d, e, f, g, h, a);
    T1 = X[8] = swapBytesQ(W[8]);
    ROUND_00_15(8, a, b, c, d, e, f, g, h);
    T1 = X[9] = swapBytesQ(W[9]);
    ROUND_00_15(9, h, a, b, c, d, e, f, g);
    T1 = X[10] = swapBytesQ(W[10]);
    ROUND_00_15(10, g, h, a, b, c, d, e, f);
    T1 = X[11] = swapBytesQ(W[11]);
    ROUND_00_15(11, f, g, h, a, b, c, d, e);
    T1 = X[12] = swapBytesQ(W[12]);
    ROUND_00_15(12, e, f, g, h, a, b, c, d);
    T1 = X[13] = swapBytesQ(W[13]);
    ROUND_00_15(13, d, e, f, g, h, a, b, c);
    T1 = X[14] = swapBytesQ(W[14]);
    ROUND_00_15(14, c, d, e, f, g, h, a, b);
    T1 = X[15] = swapBytesQ(W[15]);
    ROUND_00_15(15, b, c, d, e, f, g, h, a);
#endif

    for (i = 16; i < 80; i += 16) {
      ROUND_16_80(i, 0, a, b, c, d, e, f, g, h, X);
      ROUND_16_80(i, 1, h, a, b, c, d, e, f, g, X);
      ROUND_16_80(i, 2, g, h, a, b, c, d, e, f, X);
      ROUND_16_80(i, 3, f, g, h, a, b, c, d, e, X);
      ROUND_16_80(i, 4, e, f, g, h, a, b, c, d, X);
      ROUND_16_80(i, 5, d, e, f, g, h, a, b, c, X);
      ROUND_16_80(i, 6, c, d, e, f, g, h, a, b, X);
      ROUND_16_80(i, 7, b, c, d, e, f, g, h, a, X);
      ROUND_16_80(i, 8, a, b, c, d, e, f, g, h, X);
      ROUND_16_80(i, 9, h, a, b, c, d, e, f, g, X);
      ROUND_16_80(i, 10, g, h, a, b, c, d, e, f, X);
      ROUND_16_80(i, 11, f, g, h, a, b, c, d, e, X);
      ROUND_16_80(i, 12, e, f, g, h, a, b, c, d, X);
      ROUND_16_80(i, 13, d, e, f, g, h, a, b, c, X);
      ROUND_16_80(i, 14, c, d, e, f, g, h, a, b, X);
      ROUND_16_80(i, 15, b, c, d, e, f, g, h, a, X);
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;

    W += SHA_LBLOCK;
  }
}

int updateSHA512(sha512_ctx *c, const void *_data, size_t len)
{
  uint64_t l;
  unsigned char *p = c->u.p;
  const unsigned char *data = (const unsigned char *)_data;

  if (len == 0)
    return 1;

  l = (c->Nl + (((uint64_t) len) << 3)) & U64(0xffffffffffffffff);
  if (l < c->Nl)
    c->Nh++;
  if (sizeof(len) >= 8)
    c->Nh += (((uint64_t) len) >> 61);
  c->Nl = l;

  if (c->num != 0) {
    size_t n = sizeof(c->u) - c->num;

    if (len < n) {
      memcpy(p + c->num, data, len), c->num += (unsigned int)len;
      return 1;
    } else {
      memcpy(p + c->num, data, n), c->num = 0;
      len -= n, data += n;
      sha512_block_data_order(c, p, 1);
    }
  }

  if (len >= sizeof(c->u)) {
    if ((size_t)data % sizeof(c->u.d[0]) != 0)
      while (len >= sizeof(c->u))
        memcpy(p, data, sizeof(c->u)),
            sha512_block_data_order(c, p, 1),
            len -= sizeof(c->u), data += sizeof(c->u);
    else
      sha512_block_data_order(c, data, len / sizeof(c->u)),
          data += len, len %= sizeof(c->u), data -= len;
  }

  if (len != 0)
    memcpy(p, data, len), c->num = (int)len;

  return 1;
}

int finalSHA512(unsigned char *md, sha512_ctx *c)
{
  unsigned char *p = (unsigned char *)c->u.p;
  size_t n = c->num;

  p[n] = 0x80;
  n++;
  if (n > (sizeof(c->u) - 16)) {
    memset(p + n, 0, sizeof(c->u) - n);
    n = 0;
    sha512_block_data_order(c, p, 1);
  }

  memset(p + n, 0, sizeof(c->u) - 16 - n);
#ifdef  B_ENDIAN
  c->u.d[SHA_LBLOCK - 2] = c->Nh;
  c->u.d[SHA_LBLOCK - 1] = c->Nl;
#else
  p[sizeof(c->u) - 1] = (unsigned char)(c->Nl);
  p[sizeof(c->u) - 2] = (unsigned char)(c->Nl >> 8);
  p[sizeof(c->u) - 3] = (unsigned char)(c->Nl >> 16);
  p[sizeof(c->u) - 4] = (unsigned char)(c->Nl >> 24);
  p[sizeof(c->u) - 5] = (unsigned char)(c->Nl >> 32);
  p[sizeof(c->u) - 6] = (unsigned char)(c->Nl >> 40);
  p[sizeof(c->u) - 7] = (unsigned char)(c->Nl >> 48);
  p[sizeof(c->u) - 8] = (unsigned char)(c->Nl >> 56);
  p[sizeof(c->u) - 9] = (unsigned char)(c->Nh);
  p[sizeof(c->u) - 10] = (unsigned char)(c->Nh >> 8);
  p[sizeof(c->u) - 11] = (unsigned char)(c->Nh >> 16);
  p[sizeof(c->u) - 12] = (unsigned char)(c->Nh >> 24);
  p[sizeof(c->u) - 13] = (unsigned char)(c->Nh >> 32);
  p[sizeof(c->u) - 14] = (unsigned char)(c->Nh >> 40);
  p[sizeof(c->u) - 15] = (unsigned char)(c->Nh >> 48);
  p[sizeof(c->u) - 16] = (unsigned char)(c->Nh >> 56);
#endif

  sha512_block_data_order(c, p, 1);

  if (md == 0)
    return 0;

  switch (c->md_len) {
    case SHA224_DIGEST_LENGTH:
      for (n = 0; n < SHA224_DIGEST_LENGTH / 8; n++) {
        uint64_t t = c->h[n];

        *(md++) = (unsigned char)(t >> 56);
        *(md++) = (unsigned char)(t >> 48);
        *(md++) = (unsigned char)(t >> 40);
        *(md++) = (unsigned char)(t >> 32);
        *(md++) = (unsigned char)(t >> 24);
        *(md++) = (unsigned char)(t >> 16);
        *(md++) = (unsigned char)(t >> 8);
        *(md++) = (unsigned char)(t);
      }
      {
        uint64_t t = c->h[SHA224_DIGEST_LENGTH / 8];

        *(md++) = (unsigned char)(t >> 56);
        *(md++) = (unsigned char)(t >> 48);
        *(md++) = (unsigned char)(t >> 40);
        *(md++) = (unsigned char)(t >> 32);
      }
      break;
    case SHA256_DIGEST_LENGTH:
      for (n = 0; n < SHA256_DIGEST_LENGTH / 8; n++) {
        uint64_t t = c->h[n];

        *(md++) = (unsigned char)(t >> 56);
        *(md++) = (unsigned char)(t >> 48);
        *(md++) = (unsigned char)(t >> 40);
        *(md++) = (unsigned char)(t >> 32);
        *(md++) = (unsigned char)(t >> 24);
        *(md++) = (unsigned char)(t >> 16);
        *(md++) = (unsigned char)(t >> 8);
        *(md++) = (unsigned char)(t);
      }
      break;
    case SHA384_DIGEST_LENGTH:
      for (n = 0; n < SHA384_DIGEST_LENGTH / 8; n++) {
        uint64_t t = c->h[n];

        *(md++) = (unsigned char)(t >> 56);
        *(md++) = (unsigned char)(t >> 48);
        *(md++) = (unsigned char)(t >> 40);
        *(md++) = (unsigned char)(t >> 32);
        *(md++) = (unsigned char)(t >> 24);
        *(md++) = (unsigned char)(t >> 16);
        *(md++) = (unsigned char)(t >> 8);
        *(md++) = (unsigned char)(t);
      }
      break;
    case SHA512_DIGEST_LENGTH:
      for (n = 0; n < SHA512_DIGEST_LENGTH / 8; n++) {
        uint64_t t = c->h[n];

        *(md++) = (unsigned char)(t >> 56);
        *(md++) = (unsigned char)(t >> 48);
        *(md++) = (unsigned char)(t >> 40);
        *(md++) = (unsigned char)(t >> 32);
        *(md++) = (unsigned char)(t >> 24);
        *(md++) = (unsigned char)(t >> 16);
        *(md++) = (unsigned char)(t >> 8);
        *(md++) = (unsigned char)(t);
      }
      break;
    default:
      return 0;
  }

  return 1;
}

unsigned char *getHash(unsigned char *in, int in_len){
  static unsigned char out[HASH_LEN];
  sha512_ctx ctx;

  if(!in)
    return NULL;

  initSHA512(&ctx);
  updateSHA512(&ctx, in, in_len);
  finalSHA512(out, &ctx);

  return out;
}
