#include "common.h"
#include "crypt.h"
#include "obfuscation.h"
#include <string.h>
#include <stdint.h>

/**
 * Шифр AES в режиме CBC, с ключом и блоком по 128 бит (16 байт)
 * Источники:
 *   - openssl/include/openssl/aes.h
 *   - openssl/crypto/aes/aes_local.h
 *   - openssl/crypto/aes/aes_core.c
 *   - openssl/crypto/aes/aes_cbc.c
 *   - crypto/modes/cbc128.c
*/

#define BLOCK_LENGTH 16

#define DO_CRYPT 1
#define DO_DECRYPT 0

#define AES_MAXNR 14

typedef uint64_t u64;
typedef unsigned int u32;
typedef size_t size_t_aX;

typedef union {
    unsigned char b[8];
    u32 w[2];
    u64 d;
} uni;

typedef struct {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
} AES_KEY;

const unsigned char obfuscated_iv[BLOCK_LENGTH] = {
    0x62, 0x5e, 0xb2, 0xc3, 0x39, 0x4e, 0x4b, 0x04,
    0x27, 0x56, 0x1d, 0x94, 0x77, 0x66, 0xe8, 0x8d
};

static void RotWord(u32 *x)
{
  unsigned char *w0;
  unsigned char tmp;

  w0 = (unsigned char *)x;
  tmp = w0[0];
  w0[0] = w0[1];
  w0[1] = w0[2];
  w0[2] = w0[3];
  w0[3] = tmp;
}

static void SubWord(u32 *w)
{
  u32 x, y, a1, a2, a3, a4, a5, a6;

  x = *w;
  y = ((x & 0xFEFEFEFEu) >> 1) | ((x & 0x01010101u) << 7);
  x &= 0xDDDDDDDDu;
  x ^= y & 0x57575757u;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x1C1C1C1Cu;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x4A4A4A4Au;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x42424242u;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x64646464u;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0xE0E0E0E0u;
  a1 = x;
  a1 ^= (x & 0xF0F0F0F0u) >> 4;
  a2 = ((x & 0xCCCCCCCCu) >> 2) | ((x & 0x33333333u) << 2);
  a3 = x & a1;
  a3 ^= (a3 & 0xAAAAAAAAu) >> 1;
  a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & 0xAAAAAAAAu;
  a4 = a2 & a1;
  a4 ^= (a4 & 0xAAAAAAAAu) >> 1;
  a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & 0xAAAAAAAAu;
  a5 = (a3 & 0xCCCCCCCCu) >> 2;
  a3 ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCu;
  a4 = a5 & 0x22222222u;
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & 0x22222222u;
  a3 ^= a4;
  a5 = a3 & 0xA0A0A0A0u;
  a5 |= a5 >> 1;
  a5 ^= (a3 << 1) & 0xA0A0A0A0u;
  a4 = a5 & 0xC0C0C0C0u;
  a6 = a4 >> 2;
  a4 ^= (a5 << 2) & 0xC0C0C0C0u;
  a5 = a6 & 0x20202020u;
  a5 |= a5 >> 1;
  a5 ^= (a6 << 1) & 0x20202020u;
  a4 |= a5;
  a3 ^= a4 >> 4;
  a3 &= 0x0F0F0F0Fu;
  a2 = a3;
  a2 ^= (a3 & 0x0C0C0C0Cu) >> 2;
  a4 = a3 & a2;
  a4 ^= (a4 & 0x0A0A0A0A0Au) >> 1;
  a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & 0x0A0A0A0Au;
  a5 = a4 & 0x08080808u;
  a5 |= a5 >> 1;
  a5 ^= (a4 << 1) & 0x08080808u;
  a4 ^= a5 >> 2;
  a4 &= 0x03030303u;
  a4 ^= (a4 & 0x02020202u) >> 1;
  a4 |= a4 << 2;
  a3 = a2 & a4;
  a3 ^= (a3 & 0x0A0A0A0Au) >> 1;
  a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & 0x0A0A0A0Au;
  a3 |= a3 << 4;
  a2 = ((a1 & 0xCCCCCCCCu) >> 2) | ((a1 & 0x33333333u) << 2);
  x = a1 & a3;
  x ^= (x & 0xAAAAAAAAu) >> 1;
  x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & 0xAAAAAAAAu;
  a4 = a2 & a3;
  a4 ^= (a4 & 0xAAAAAAAAu) >> 1;
  a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & 0xAAAAAAAAu;
  a5 = (x & 0xCCCCCCCCu) >> 2;
  x ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCu;
  a4 = a5 & 0x22222222u;
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & 0x22222222u;
  x ^= a4;
  y = ((x & 0xFEFEFEFEu) >> 1) | ((x & 0x01010101u) << 7);
  x &= 0x39393939u;
  x ^= y & 0x3F3F3F3Fu;
  y = ((y & 0xFCFCFCFCu) >> 2) | ((y & 0x03030303u) << 6);
  x ^= y & 0x97979797u;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x9B9B9B9Bu;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x3C3C3C3Cu;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0xDDDDDDDDu;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x72727272u;
  x ^= 0x63636363u;
  *w = x;
}

static void XtimeWord(u32 *w)
{
  u32 a, b;

  a = *w;
  b = a & 0x80808080u;
  a ^= b;
  b -= b >> 7;
  b &= 0x1B1B1B1Bu;
  b ^= a << 1;
  *w = b;
}

static void KeyExpansion(const unsigned char *key, u64 *w, int nr, int nk)
{
  u32 rcon;
  uni prev;
  u32 temp;
  int i, n;

  memcpy(w, key, nk*4);
  memcpy(&rcon, "\1\0\0\0", 4);
  n = nk/2;
  prev.d = w[n-1];
  for (i = n; i < (nr+1)*2; i++) {
    temp = prev.w[1];
    if (i % n == 0) {
      RotWord(&temp);
      SubWord(&temp);
      temp ^= rcon;
      XtimeWord(&rcon);
    } else if (nk > 6 && i % n == 2) {
      SubWord(&temp);
    }
    prev.d = w[i-n];
    prev.w[0] ^= temp;
    prev.w[1] ^= prev.w[0];
    w[i] = prev.d;
  }
}

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key){
  u64 *rk;

  if (!userKey || !key)
    return -1;
  if (bits != 128 && bits != 192 && bits != 256)
    return -2;

  rk = (u64*)key->rd_key;

  if (bits == 128)
    key->rounds = 10;
  else if (bits == 192)
    key->rounds = 12;
  else
    key->rounds = 14;

  KeyExpansion(userKey, rk, key->rounds, bits/32);
  return 0;
}

int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{
  return AES_set_encrypt_key(userKey, bits, key);
}

static void AddRoundKey(u64 *state, const u64 *w)
{
  state[0] ^= w[0];
  state[1] ^= w[1];
}

static void SubLong(u64 *w)
{
  u64 x, y, a1, a2, a3, a4, a5, a6;

  x = *w;
  y = ((x & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((x & U64(0x0101010101010101)) << 7);
  x &= U64(0xDDDDDDDDDDDDDDDD);
  x ^= y & U64(0x5757575757575757);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x1C1C1C1C1C1C1C1C);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x4A4A4A4A4A4A4A4A);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x4242424242424242);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x6464646464646464);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0xE0E0E0E0E0E0E0E0);
  a1 = x;
  a1 ^= (x & U64(0xF0F0F0F0F0F0F0F0)) >> 4;
  a2 = ((x & U64(0xCCCCCCCCCCCCCCCC)) >> 2) | ((x & U64(0x3333333333333333)) << 2);
  a3 = x & a1;
  a3 ^= (a3 & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
  a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & U64(0xAAAAAAAAAAAAAAAA);
  a4 = a2 & a1;
  a4 ^= (a4 & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
  a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & U64(0xAAAAAAAAAAAAAAAA);
  a5 = (a3 & U64(0xCCCCCCCCCCCCCCCC)) >> 2;
  a3 ^= ((a4 << 2) ^ a4) & U64(0xCCCCCCCCCCCCCCCC);
  a4 = a5 & U64(0x2222222222222222);
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & U64(0x2222222222222222);
  a3 ^= a4;
  a5 = a3 & U64(0xA0A0A0A0A0A0A0A0);
  a5 |= a5 >> 1;
  a5 ^= (a3 << 1) & U64(0xA0A0A0A0A0A0A0A0);
  a4 = a5 & U64(0xC0C0C0C0C0C0C0C0);
  a6 = a4 >> 2;
  a4 ^= (a5 << 2) & U64(0xC0C0C0C0C0C0C0C0);
  a5 = a6 & U64(0x2020202020202020);
  a5 |= a5 >> 1;
  a5 ^= (a6 << 1) & U64(0x2020202020202020);
  a4 |= a5;
  a3 ^= a4 >> 4;
  a3 &= U64(0x0F0F0F0F0F0F0F0F);
  a2 = a3;
  a2 ^= (a3 & U64(0x0C0C0C0C0C0C0C0C)) >> 2;
  a4 = a3 & a2;
  a4 ^= (a4 & U64(0x0A0A0A0A0A0A0A0A)) >> 1;
  a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & U64(0x0A0A0A0A0A0A0A0A);
  a5 = a4 & U64(0x0808080808080808);
  a5 |= a5 >> 1;
  a5 ^= (a4 << 1) & U64(0x0808080808080808);
  a4 ^= a5 >> 2;
  a4 &= U64(0x0303030303030303);
  a4 ^= (a4 & U64(0x0202020202020202)) >> 1;
  a4 |= a4 << 2;
  a3 = a2 & a4;
  a3 ^= (a3 & U64(0x0A0A0A0A0A0A0A0A)) >> 1;
  a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & U64(0x0A0A0A0A0A0A0A0A);
  a3 |= a3 << 4;
  a2 = ((a1 & U64(0xCCCCCCCCCCCCCCCC)) >> 2) | ((a1 & U64(0x3333333333333333)) << 2);
  x = a1 & a3;
  x ^= (x & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
  x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & U64(0xAAAAAAAAAAAAAAAA);
  a4 = a2 & a3;
  a4 ^= (a4 & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
  a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & U64(0xAAAAAAAAAAAAAAAA);
  a5 = (x & U64(0xCCCCCCCCCCCCCCCC)) >> 2;
  x ^= ((a4 << 2) ^ a4) & U64(0xCCCCCCCCCCCCCCCC);
  a4 = a5 & U64(0x2222222222222222);
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & U64(0x2222222222222222);
  x ^= a4;
  y = ((x & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((x & U64(0x0101010101010101)) << 7);
  x &= U64(0x3939393939393939);
  x ^= y & U64(0x3F3F3F3F3F3F3F3F);
  y = ((y & U64(0xFCFCFCFCFCFCFCFC)) >> 2) | ((y & U64(0x0303030303030303)) << 6);
  x ^= y & U64(0x9797979797979797);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x9B9B9B9B9B9B9B9B);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x3C3C3C3C3C3C3C3C);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0xDDDDDDDDDDDDDDDD);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x7272727272727272);
  x ^= U64(0x6363636363636363);
  *w = x;
}

static void ShiftRows(u64 *state)
{
  unsigned char s[4];
  unsigned char *s0;
  int r;

  s0 = (unsigned char *)state;
  for (r = 0; r < 4; r++) {
    s[0] = s0[0*4 + r];
    s[1] = s0[1*4 + r];
    s[2] = s0[2*4 + r];
    s[3] = s0[3*4 + r];
    s0[0*4 + r] = s[(r+0) % 4];
    s0[1*4 + r] = s[(r+1) % 4];
    s0[2*4 + r] = s[(r+2) % 4];
    s0[3*4 + r] = s[(r+3) % 4];
  }
}

static void XtimeLong(u64 *w)
{
  u64 a, b;

  a = *w;
  b = a & U64(0x8080808080808080);
  a ^= b;
  b -= b >> 7;
  b &= U64(0x1B1B1B1B1B1B1B1B);
  b ^= a << 1;
  *w = b;
}

static void MixColumns(u64 *state)
{
  uni s1;
  uni s;
  int c;

  for (c = 0; c < 2; c++) {
    s1.d = state[c];
    s.d = s1.d;
    s.d ^= ((s.d & U64(0xFFFF0000FFFF0000)) >> 16)
           | ((s.d & U64(0x0000FFFF0000FFFF)) << 16);
    s.d ^= ((s.d & U64(0xFF00FF00FF00FF00)) >> 8)
           | ((s.d & U64(0x00FF00FF00FF00FF)) << 8);
    s.d ^= s1.d;
    XtimeLong(&s1.d);
    s.d ^= s1.d;
    s.b[0] ^= s1.b[1];
    s.b[1] ^= s1.b[2];
    s.b[2] ^= s1.b[3];
    s.b[3] ^= s1.b[0];
    s.b[4] ^= s1.b[5];
    s.b[5] ^= s1.b[6];
    s.b[6] ^= s1.b[7];
    s.b[7] ^= s1.b[4];
    state[c] = s.d;
  }
}

static void Cipher(const unsigned char *in, unsigned char *out, const u64 *w, int nr)
{
  u64 state[2];
  int i;

  memcpy(state, in, 16);

  AddRoundKey(state, w);

  for (i = 1; i < nr; i++) {
    SubLong(&state[0]);
    SubLong(&state[1]);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, w + i*2);
  }

  SubLong(&state[0]);
  SubLong(&state[1]);
  ShiftRows(state);
  AddRoundKey(state, w + nr*2);

  memcpy(out, state, 16);
}

void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
  const u64 *rk;

  rk = (u64*)key->rd_key;

  Cipher(in, out, rk, key->rounds);
}

void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key,
                           unsigned char ivec[16])
{
  size_t n;
  const unsigned char *iv = ivec;

  if (len == 0)
    return;

  if (((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
    while (len >= 16) {
      for (n = 0; n < 16; ++n)
        out[n] = in[n] ^ iv[n];
      AES_encrypt(out, out, key);
      iv = out;
      len -= 16;
      in += 16;
      out += 16;
    }
  } else {
    while (len >= 16) {
      for (n = 0; n < 16; n += sizeof(size_t))
        *(size_t_aX *)(out + n) =
            *(size_t_aX *)(in + n) ^ *(size_t_aX *)(iv + n);
      AES_encrypt(out, out, key);
      iv = out;
      len -= 16;
      in += 16;
      out += 16;
    }
  }
  while (len) {
    for (n = 0; n < 16 && n < len; ++n)
      out[n] = in[n] ^ iv[n];
    for (; n < 16; ++n)
      out[n] = iv[n];
    AES_encrypt(out, out, key);
    iv = out;
    if (len <= 16)
      break;
    len -= 16;
    in += 16;
    out += 16;
  }
  if (ivec != iv)
    memcpy(ivec, iv, 16);
}

static void InvShiftRows(u64 *state)
{
  unsigned char s[4];
  unsigned char *s0;
  int r;

  s0 = (unsigned char *)state;
  for (r = 0; r < 4; r++) {
    s[0] = s0[0*4 + r];
    s[1] = s0[1*4 + r];
    s[2] = s0[2*4 + r];
    s[3] = s0[3*4 + r];
    s0[0*4 + r] = s[(4-r) % 4];
    s0[1*4 + r] = s[(5-r) % 4];
    s0[2*4 + r] = s[(6-r) % 4];
    s0[3*4 + r] = s[(7-r) % 4];
  }
}

static void InvSubLong(u64 *w)
{
  u64 x, y, a1, a2, a3, a4, a5, a6;

  x = *w;
  x ^= U64(0x6363636363636363);
  y = ((x & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((x & U64(0x0101010101010101)) << 7);
  x &= U64(0xFDFDFDFDFDFDFDFD);
  x ^= y & U64(0x5E5E5E5E5E5E5E5E);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0xF3F3F3F3F3F3F3F3);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0xF5F5F5F5F5F5F5F5);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x7878787878787878);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x7777777777777777);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x1515151515151515);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0xA5A5A5A5A5A5A5A5);
  a1 = x;
  a1 ^= (x & U64(0xF0F0F0F0F0F0F0F0)) >> 4;
  a2 = ((x & U64(0xCCCCCCCCCCCCCCCC)) >> 2) | ((x & U64(0x3333333333333333)) << 2);
  a3 = x & a1;
  a3 ^= (a3 & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
  a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & U64(0xAAAAAAAAAAAAAAAA);
  a4 = a2 & a1;
  a4 ^= (a4 & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
  a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & U64(0xAAAAAAAAAAAAAAAA);
  a5 = (a3 & U64(0xCCCCCCCCCCCCCCCC)) >> 2;
  a3 ^= ((a4 << 2) ^ a4) & U64(0xCCCCCCCCCCCCCCCC);
  a4 = a5 & U64(0x2222222222222222);
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & U64(0x2222222222222222);
  a3 ^= a4;
  a5 = a3 & U64(0xA0A0A0A0A0A0A0A0);
  a5 |= a5 >> 1;
  a5 ^= (a3 << 1) & U64(0xA0A0A0A0A0A0A0A0);
  a4 = a5 & U64(0xC0C0C0C0C0C0C0C0);
  a6 = a4 >> 2;
  a4 ^= (a5 << 2) & U64(0xC0C0C0C0C0C0C0C0);
  a5 = a6 & U64(0x2020202020202020);
  a5 |= a5 >> 1;
  a5 ^= (a6 << 1) & U64(0x2020202020202020);
  a4 |= a5;
  a3 ^= a4 >> 4;
  a3 &= U64(0x0F0F0F0F0F0F0F0F);
  a2 = a3;
  a2 ^= (a3 & U64(0x0C0C0C0C0C0C0C0C)) >> 2;
  a4 = a3 & a2;
  a4 ^= (a4 & U64(0x0A0A0A0A0A0A0A0A)) >> 1;
  a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & U64(0x0A0A0A0A0A0A0A0A);
  a5 = a4 & U64(0x0808080808080808);
  a5 |= a5 >> 1;
  a5 ^= (a4 << 1) & U64(0x0808080808080808);
  a4 ^= a5 >> 2;
  a4 &= U64(0x0303030303030303);
  a4 ^= (a4 & U64(0x0202020202020202)) >> 1;
  a4 |= a4 << 2;
  a3 = a2 & a4;
  a3 ^= (a3 & U64(0x0A0A0A0A0A0A0A0A)) >> 1;
  a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & U64(0x0A0A0A0A0A0A0A0A);
  a3 |= a3 << 4;
  a2 = ((a1 & U64(0xCCCCCCCCCCCCCCCC)) >> 2) | ((a1 & U64(0x3333333333333333)) << 2);
  x = a1 & a3;
  x ^= (x & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
  x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & U64(0xAAAAAAAAAAAAAAAA);
  a4 = a2 & a3;
  a4 ^= (a4 & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
  a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & U64(0xAAAAAAAAAAAAAAAA);
  a5 = (x & U64(0xCCCCCCCCCCCCCCCC)) >> 2;
  x ^= ((a4 << 2) ^ a4) & U64(0xCCCCCCCCCCCCCCCC);
  a4 = a5 & U64(0x2222222222222222);
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & U64(0x2222222222222222);
  x ^= a4;
  y = ((x & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((x & U64(0x0101010101010101)) << 7);
  x &= U64(0xB5B5B5B5B5B5B5B5);
  x ^= y & U64(0x4040404040404040);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x8080808080808080);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x1616161616161616);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0xEBEBEBEBEBEBEBEB);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x9797979797979797);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0xFBFBFBFBFBFBFBFB);
  y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
  x ^= y & U64(0x7D7D7D7D7D7D7D7D);
  *w = x;
}

static void InvMixColumns(u64 *state)
{
  uni s1;
  uni s;
  int c;

  for (c = 0; c < 2; c++) {
    s1.d = state[c];
    s.d = s1.d;
    s.d ^= ((s.d & U64(0xFFFF0000FFFF0000)) >> 16)
           | ((s.d & U64(0x0000FFFF0000FFFF)) << 16);
    s.d ^= ((s.d & U64(0xFF00FF00FF00FF00)) >> 8)
           | ((s.d & U64(0x00FF00FF00FF00FF)) << 8);
    s.d ^= s1.d;
    XtimeLong(&s1.d);
    s.d ^= s1.d;
    s.b[0] ^= s1.b[1];
    s.b[1] ^= s1.b[2];
    s.b[2] ^= s1.b[3];
    s.b[3] ^= s1.b[0];
    s.b[4] ^= s1.b[5];
    s.b[5] ^= s1.b[6];
    s.b[6] ^= s1.b[7];
    s.b[7] ^= s1.b[4];
    XtimeLong(&s1.d);
    s1.d ^= ((s1.d & U64(0xFFFF0000FFFF0000)) >> 16)
            | ((s1.d & U64(0x0000FFFF0000FFFF)) << 16);
    s.d ^= s1.d;
    XtimeLong(&s1.d);
    s1.d ^= ((s1.d & U64(0xFF00FF00FF00FF00)) >> 8)
            | ((s1.d & U64(0x00FF00FF00FF00FF)) << 8);
    s.d ^= s1.d;
    state[c] = s.d;
  }
}

static void InvCipher(const unsigned char *in, unsigned char *out, const u64 *w, int nr)

{
  u64 state[2];
  int i;

  memcpy(state, in, 16);

  AddRoundKey(state, w + nr*2);

  for (i = nr - 1; i > 0; i--) {
    InvShiftRows(state);
    InvSubLong(&state[0]);
    InvSubLong(&state[1]);
    AddRoundKey(state, w + i*2);
    InvMixColumns(state);
  }

  InvShiftRows(state);
  InvSubLong(&state[0]);
  InvSubLong(&state[1]);
  AddRoundKey(state, w);

  memcpy(out, state, 16);
}

void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
  const u64 *rk;

  rk = (u64*)key->rd_key;

  InvCipher(in, out, rk, key->rounds);
}

void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key,
                           unsigned char ivec[16])
{
  size_t n;
  union {
      size_t t[16 / sizeof(size_t)];
      unsigned char c[16];
  } tmp;

  if (len == 0)
    return;

  if (in != out) {
    const unsigned char *iv = ivec;

    if (((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
      while (len >= 16) {
        AES_decrypt(in, out, key);
        for (n = 0; n < 16; ++n)
          out[n] ^= iv[n];
        iv = in;
        len -= 16;
        in += 16;
        out += 16;
      }
    } else if (16 % sizeof(size_t) == 0) {
      while (len >= 16) {
        size_t_aX *out_t = (size_t_aX *)out;
        size_t_aX *iv_t = (size_t_aX *)iv;

        AES_decrypt(in, out, key);
        for (n = 0; n < 16 / sizeof(size_t); n++)
          out_t[n] ^= iv_t[n];
        iv = in;
        len -= 16;
        in += 16;
        out += 16;
      }
    }
    if (ivec != iv)
      memcpy(ivec, iv, 16);
  } else {
    if (((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
      unsigned char c;
      while (len >= 16) {
        AES_decrypt(in, tmp.c, key);
        for (n = 0; n < 16; ++n) {
          c = in[n];
          out[n] = tmp.c[n] ^ ivec[n];
          ivec[n] = c;
        }
        len -= 16;
        in += 16;
        out += 16;
      }
    } else if (16 % sizeof(size_t) == 0) {
      while (len >= 16) {
        size_t c;
        size_t_aX *out_t = (size_t_aX *)out;
        size_t_aX *ivec_t = (size_t_aX *)ivec;
        const size_t_aX *in_t = (const size_t_aX *)in;

        AES_decrypt(in, tmp.c, key);
        for (n = 0; n < 16 / sizeof(size_t); n++) {
          c = in_t[n];
          out_t[n] = tmp.t[n] ^ ivec_t[n];
          ivec_t[n] = c;
        }
        len -= 16;
        in += 16;
        out += 16;
      }
    }
  }
  while (len) {
    unsigned char c;
    AES_decrypt(in, tmp.c, key);
    for (n = 0; n < 16 && n < len; ++n) {
      c = in[n];
      out[n] = tmp.c[n] ^ ivec[n];
      ivec[n] = c;
    }
    if (len <= 16) {
      for (; n < 16; ++n)
        ivec[n] = in[n];
      break;
    }
    len -= 16;
    in += 16;
    out += 16;
  }
}

void AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const AES_KEY *key, unsigned char *ivec,
                     const int enc)
{
  if (enc)
    CRYPTO_cbc128_encrypt(in, out, len, key, ivec);
  else
    CRYPTO_cbc128_decrypt(in, out, len, key, ivec);
}

int getEncryptedDataLen(int data_len){
  int block_count = data_len / BLOCK_LENGTH + (data_len % BLOCK_LENGTH ? 1 : 0);
  return block_count * BLOCK_LENGTH;
}

int encryptData(unsigned char *in, int in_len, unsigned char* key, int key_len, unsigned char *out, int out_len){
  AES_KEY aes_key;
  unsigned char iv[BLOCK_LENGTH];
  int final_len = getEncryptedDataLen(in_len);

  if(!in || !out || !key)
    return 0;
  if(key_len != KEY_LENGTH)
    return 0;
  if(out_len < final_len)
    return 0;

  if(!getRealSecret(obfuscated_iv, sizeof(obfuscated_iv), iv, sizeof(iv)))
    return 0;
  AES_set_encrypt_key(key, KEY_LENGTH * 8, &aes_key);
  AES_cbc_encrypt(in, out, in_len, &aes_key, iv, DO_CRYPT);
  return final_len;
}

int decryptData(unsigned char *in, int in_len, unsigned char* key, int key_len, unsigned char *out, int out_len){
  AES_KEY aes_key;
  unsigned char iv[BLOCK_LENGTH];

  if(!in || !out || !key)
    return 0;
  if(key_len != KEY_LENGTH)
    return 0;
  if(out_len < in_len || in_len % BLOCK_LENGTH != 0)
    return 0;

  if(!getRealSecret(obfuscated_iv, sizeof(obfuscated_iv), iv, sizeof(iv)))
    return 0;
  AES_set_decrypt_key(key, KEY_LENGTH * 8, &aes_key);
  AES_cbc_encrypt(in, out, in_len, &aes_key, iv, DO_DECRYPT);
  return in_len;
}
