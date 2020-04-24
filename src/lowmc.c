#include <string.h>
#include <stdint.h>

#include "../include/lowmc.h"
#include "../include/picnic.h"
#include "../include/predefined_constants.h"


void LowMC(uint8_t* out, uint8_t* in, uint8_t* key, picnic_params_t* params) {
  uint8_t tmp[MAX_STATE_SIZE];

  matrix_mult(out, key, PL_MATRIX, -1, params); // round is not needed
  block_xor_inplace(out, in, params);
  block_xor_inplace(out, const_pointer(CL_CONST, -1, params), params); // round is not needed


  for (int i = 0; i < params->lowmc_rounds - 1; i++) {
    substitution(out);
    generate_round_key(tmp, key, i, params);
    block_xor_inplace(tmp, out, params);
    matrix_mult(out, tmp, Z_UPPER, i, params);
    matrix_mult_z_lower(out, tmp, i, params);
  }

  substitution(out);
  generate_round_key(tmp, key, params->lowmc_rounds - 1, params);
  block_xor_inplace(tmp, out, params);
  matrix_mult(out, tmp, Z_LAST, params->lowmc_rounds - 1, params);
}

void block_xor_inplace(uint8_t* state, const uint8_t* data, picnic_params_t* params) {
  for (int i = 0; i < params->state_size; i++) {
    state[i] ^= data[i];
  }
}

void block_xor(uint8_t* out, uint8_t* in1, uint8_t* in2, picnic_params_t* params) {
  for (int i = 0; i < params->state_size; i++) {
    out[i] = in1[i] ^ in2[i];
  }
}

void matrix_mult(uint8_t* out, uint8_t* in, int mat_type, int round, picnic_params_t* params) {
  memset(out, 0x00, params->state_size);
  uint8_t tmp[MAX_STATE_SIZE];
  const uint8_t* m_ptr = matrix_pointer(mat_type, round, params);
  int limit = (mat_type == Z_UPPER || mat_type == PN_MATRIX ? PICNIC_SBOX_BITS : params->state_size << 3);

  for (int i = 0; i < limit; i++) {
    for (int j = 0; j < params->state_size; j++) {
      tmp[j] = in[j] & m_ptr[i * params->state_size + j];
    }

    int delta = params->state_size >> 1;
    while (delta > 0) {
      for (int k = 0; k < delta; k++) {
        tmp[k] ^= tmp[k + delta];
      }
      if (delta == 3) // for 24 byte state size
      {
        tmp[1] ^= tmp[2];
      }
      delta >>= 1;
    }

    tmp[0] ^= (tmp[0] >> 4);
    tmp[0] ^= (tmp[0] >> 2);
    tmp[0] ^= (tmp[0] >> 1);

    out[i >> 3] |= (tmp[0] & 1) << (7 - (i & 0x07));
  }
}

void matrix_mult_z_lower(uint8_t* out, uint8_t* in, int round, picnic_params_t* params) {
  //precond: affected bits must be zero, which is done by matrix_mult()
  uint8_t tmp[MAX_STATE_SIZE];
  const uint8_t* m_ptr = matrix_pointer(Z_LOWER, round, params);

  for (int i = PICNIC_SBOX_BITS; i < params->state_size << 3; i++) {
    for (int j = 0; j < 5; j++) {
      tmp[j] = in[j] & m_ptr[(i - PICNIC_SBOX_BITS) * 5 + j];
    }

    tmp[3] ^= tmp[4];
    tmp[2] ^= tmp[3];
    tmp[1] ^= tmp[2];
    tmp[0] ^= tmp[1];

    tmp[0] ^= (tmp[0] >> 4);
    tmp[0] ^= (tmp[0] >> 2);
    tmp[0] ^= (tmp[0] >> 1);

    if (i >= 40) {
      int byte_pos = 5 + ((i - 40) >> 3);
      int bit_pos = 7 - ((i - 40) & 0x07);

      uint8_t bit = (in[byte_pos] & (0x01 << bit_pos)) >> bit_pos;
      tmp[0] ^= bit;
    }

    out[i >> 3] |= (tmp[0] & 1) << (7 - (i & 0x07));
  }
}

void substitution(uint8_t* state) {
  for (int i = 0; i < 30; i += 3) {
    uint8_t c = (state[i >> 3] >> (7 - (i & 0x07))) & 1;
    uint8_t b = (state[(i + 1) >> 3] >> (7 - ((i + 1) & 0x07))) & 1;
    uint8_t a = (state[(i + 2) >> 3] >> (7 - ((i + 2) & 0x07))) & 1;

    uint8_t ab = a & b;
    uint8_t ac = a & c;
    uint8_t bc = b & c;

    state[i >> 3] ^= (a ^ b ^ ab) << (7 - (i & 0x07));
    state[(i + 1) >> 3] ^= (a ^ ac) << (7 - ((i + 1) & 0x07));
    state[(i + 2) >> 3] ^= bc << (7 - ((i + 2) & 0x07));
  }
}

void generate_round_key(uint8_t* out, uint8_t* key, int round, picnic_params_t* params) {
  const uint8_t* CN_ptr = const_pointer(CN_CONST, round, params);

  matrix_mult(out, key, PN_MATRIX, round, params);
  
  out[0] ^= CN_ptr[0];
  out[1] ^= CN_ptr[1];
  out[2] ^= CN_ptr[2];
  out[3] ^= CN_ptr[3];
}
