#include <stdint.h>
#include <string.h>

#include "../include/lowmc.h"
#include "../include/lowmc_mpc.h"
#include "../include/picnic.h"
#include "../include/predefined_constants.h"
#include "../include/sha3.h"

void LowMC_mpc(uint8_t** outputs, uint8_t* input, uint8_t** keys, uint8_t** tapes,
               picnic_params_t* params) {
  uint8_t* tmp = (uint8_t*) malloc(3 * params->state_size * sizeof(uint8_t));
  uint8_t* tmps[3];
  tmps[0] = tmp;
  tmps[1] = tmp + params->state_size;
  tmps[2] = tmp + 2 * params->state_size;

  matrix_mult_mpc(outputs, keys, PL_MATRIX, -1, params); // round not needed
  block_xor_const_inplace_mpc(outputs, input, params);
  block_xor_const_inplace_mpc(outputs, const_pointer(CL_CONST, -1, params),
                              params); // round is not needed

  for (int i = 0; i < params->lowmc_rounds - 1; i++) {
    substitution_mpc(outputs, tapes, i);
    generate_round_key_mpc(tmps, keys, i, params);
    block_xor_inplace_mpc(tmps, outputs, params);
    matrix_mult_mpc(outputs, tmps, Z_UPPER, i, params);
    matrix_mult_z_lower_mpc(outputs, tmps, i, params);
  }

  substitution_mpc(outputs, tapes, params->lowmc_rounds - 1);
  generate_round_key_mpc(tmps, keys, params->lowmc_rounds - 1, params);
  block_xor_inplace_mpc(tmps, outputs, params);
  matrix_mult_mpc(outputs, tmps, Z_LAST, params->lowmc_rounds - 1, params);

  free(tmp);
}

void matrix_mult_mpc(uint8_t** out, uint8_t** in, int mat_type, int round,
                     picnic_params_t* params) {

  memset(out[0], 0x00, params->state_size);
  memset(out[1], 0x00, params->state_size);
  memset(out[2], 0x00, params->state_size);

  const uint8_t* m_ptr = matrix_pointer(mat_type, round, params);
  uint8_t *tmp2 = (uint8_t*) malloc(params->state_size * sizeof(uint8_t));

  int limit = (mat_type == Z_UPPER || mat_type == PN_MATRIX ? PICNIC_SBOX_BITS : params->state_size << 3);

  for (int i = 0; i < limit; i++) {
    for (int pl = 0; pl < 3; pl++) {
      for (int j = 0; j < params->state_size; j++) {
        tmp2[j] = in[pl][j] & m_ptr[i * params->state_size + j];
      }

      int delta = params->state_size >> 1;
      while (delta > 0) {
        for (int k = 0; k < delta; k++) {
          tmp2[k] ^= tmp2[k + delta];
        }
        if (delta == 3) // for 24 byte state size
        {
          tmp2[1] ^= tmp2[2];
        }
        delta >>= 1;
      }

      tmp2[0] ^= (tmp2[0] >> 4);
      tmp2[0] ^= (tmp2[0] >> 2);
      tmp2[0] ^= (tmp2[0] >> 1);

      out[pl][i >> 3] |= (tmp2[0] & 1) << (7 - (i & 7));
    }
  }

  free(tmp2);
}

void matrix_mult_z_lower_mpc(uint8_t** out, uint8_t** in, int round, picnic_params_t* params) {
  // precond: affected bits must be zero, which is done by matrix_mult()

  uint8_t tmp[5];
  const uint8_t* m_ptr = matrix_pointer(Z_LOWER, round, params);

  for (int i = PICNIC_SBOX_BITS; i < params->state_size << 3; i++) {
    for (int pl = 0; pl < 3; pl++)
	{
		for (int j = 0; j < 5; j++) {
		  tmp[j] = in[pl][j] & m_ptr[(i - PICNIC_SBOX_BITS) * 5 + j];
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
		  int bit_pos = 7 - ((i - 40) & 7);

		  uint8_t bit = (in[pl][byte_pos] & (0x01 << bit_pos)) >> bit_pos;
		  tmp[0] ^= bit;
		}

		out[pl][i >> 3] |= (tmp[0] & 1) << (7 - (i & 7));
    }
  }

}


void block_xor_const_inplace_mpc(uint8_t** state, const uint8_t* data, picnic_params_t* params) {
  for (int i = 0; i < params->state_size; i++) {
    state[0][i] ^= data[i]; // only the first party
  }
}

void block_xor_inplace_mpc(uint8_t** state, uint8_t** data, picnic_params_t* params) {
  for (int pl = 0; pl < 3; pl++) {
    for (int i = 0; i < params->state_size; i++) {
      state[pl][i] ^= data[pl][i];
    }
  }
}

void substitution_mpc(uint8_t** state, uint8_t** tapes, int rnds) {
  uint8_t a[3];
  uint8_t b[3];
  uint8_t c[3];

  uint8_t ab[3];
  uint8_t ac[3];
  uint8_t bc[3];

  for (int i = 0; i < 30; i += 3) {
    int bit0 = 30 * rnds + i;
    int bit1 = 30 * rnds + i + 1;
    int bit2 = 30 * rnds + i + 2;

    for (int pl = 0; pl < 3; pl++) {
      c[pl] = (state[pl][i >> 3] >> (7 - (i & 7))) & 1;
      b[pl] = (state[pl][(i + 1) >> 3] >> (7 - ((i + 1) & 7))) & 1;
      a[pl] = (state[pl][(i + 2) >> 3] >> (7 - ((i + 2) & 7))) & 1;
    }

    for (int pl = 0; pl < 3; pl++) {
      ab[pl] = (a[pl] & b[pl]);
	  ab[pl] ^= (a[(pl + 1) % 3] & b[pl]);
	  ab[pl] ^= (a[pl] & b[(pl + 1) % 3]);
	  ab[pl] ^= ((tapes[pl][(bit0 >> 3)] ^ tapes[(pl + 1) % 3][(bit0 >> 3)]) >> (7 - (bit0 & 7))) & 1;
      
	  bc[pl] = (b[pl] & c[pl]);
	  bc[pl] ^= (b[(pl + 1) % 3] & c[pl]);
	  bc[pl] ^= (b[pl] & c[(pl + 1) % 3]);
	  bc[pl] ^= ((tapes[pl][(bit1 >> 3)] ^ tapes[(pl + 1) % 3][(bit1 >> 3)]) >> (7 - (bit1 & 7))) & 1;

      ac[pl] = (a[pl] & c[pl]);
	  ac[pl] ^= (a[(pl + 1) % 3] & c[pl]);
	  ac[pl] ^= (a[pl] & c[(pl + 1) % 3]);
	  ac[pl] ^= ((tapes[pl][(bit2 >> 3)] ^ tapes[(pl + 1) % 3][(bit2 >> 3)]) >> (7 - (bit2 & 7))) & 1;
    }

    // write interparty-communication back to the tape
    for (int pl = 0; pl < 3; pl++) {
      tapes[pl][bit0 >> 3] &= ~(1 << (7 - (bit0 & 7)));
      tapes[pl][bit1 >> 3] &= ~(1 << (7 - (bit1 & 7)));
      tapes[pl][bit2 >> 3] &= ~(1 << (7 - (bit2 & 7)));

      tapes[pl][bit0 >> 3] |= (ab[pl] << (7 - (bit0 & 7)));
      tapes[pl][bit1 >> 3] |= (bc[pl] << (7 - (bit1 & 7)));
      tapes[pl][bit2 >> 3] |= (ac[pl] << (7 - (bit2 & 7)));
    }

    for (int pl = 0; pl < 3; pl++) {
      state[pl][i >> 3] ^= (a[pl] ^ b[pl] ^ ab[pl]) << (7 - (i & 7));
      state[pl][(i + 1) >> 3] ^= (a[pl] ^ ac[pl]) << (7 - ((i + 1) & 7));
      state[pl][(i + 2) >> 3] ^= bc[pl] << (7 - ((i + 2) & 7));
    }
  }
}

void generate_round_key_mpc(uint8_t** out, uint8_t** keys, int round, picnic_params_t* params) {
  const uint8_t* CN_ptr = const_pointer(CN_CONST, round, params);
  matrix_mult_mpc(out, keys, PN_MATRIX, round, params);
 
  out[0][0] ^= CN_ptr[0];
  out[0][1] ^= CN_ptr[1];
  out[0][2] ^= CN_ptr[2];
  out[0][3] ^= CN_ptr[3];
}

/*** For Verification ***/

void LowMC_mpc_verify(uint8_t** outputs, uint8_t* input, uint8_t** keys, uint8_t** tapes,
                      uint8_t challenge, uint8_t* communication, picnic_params_t* params) {
  uint8_t tmp0[MAX_STATE_SIZE];
  uint8_t tmp1[MAX_STATE_SIZE];
  uint8_t* tmps[2];
  tmps[0] = tmp0;
  tmps[1] = tmp1;

  matrix_mult_mpc_verify(outputs, keys, PL_MATRIX, -1, params); // round not needed
  block_xor_const_inplace_mpc_verify(outputs, input, challenge, params);
  block_xor_const_inplace_mpc_verify(outputs, const_pointer(CL_CONST, -1, params), challenge,
                                     params); // round is not needed

  for (int i = 0; i < params->lowmc_rounds - 1; i++) {
    substitution_mpc_verify(outputs, tapes, communication, i);
    generate_round_key_mpc_verify(tmps, keys, i, challenge, params);
    block_xor_inplace_mpc_verify(tmps, outputs, params);
    matrix_mult_mpc_verify(outputs, tmps, Z_UPPER, i, params);
    matrix_mult_z_lower_mpc_verify(outputs, tmps, i, params);
  }

  substitution_mpc_verify(outputs, tapes, communication, params->lowmc_rounds - 1);
  generate_round_key_mpc_verify(tmps, keys, params->lowmc_rounds - 1, challenge, params);
  block_xor_inplace_mpc_verify(tmps, outputs, params);
  matrix_mult_mpc_verify(outputs, tmps, Z_LAST, params->lowmc_rounds - 1, params);
}

void matrix_mult_mpc_verify(uint8_t** out, uint8_t** in, int mat_type, int round,
                            picnic_params_t* params) {
  memset(out[0], 0x00, params->state_size);
  memset(out[1], 0x00, params->state_size);

  const uint8_t* m_ptr = matrix_pointer(mat_type, round, params);

  uint8_t tmp2[MAX_STATE_SIZE];
  int limit = (mat_type == Z_UPPER || mat_type == PN_MATRIX ? PICNIC_SBOX_BITS : params->state_size << 3);

  for (int i = 0; i < limit; i++) {
    for (int pl = 0; pl < 2; pl++) {
      for (int j = 0; j < params->state_size; j++) {
        tmp2[j] = in[pl][j] & m_ptr[i * params->state_size + j];
      }

      int delta = params->state_size >> 1;
      while (delta > 0) {
        for (int k = 0; k < delta; k++) {
          tmp2[k] ^= tmp2[k + delta];
        }
        if (delta == 3) // for 24 byte state size
        {
          tmp2[1] ^= tmp2[2];
        }
        delta >>= 1;
      }

      tmp2[0] ^= (tmp2[0] >> 4);
      tmp2[0] ^= (tmp2[0] >> 2);
      tmp2[0] ^= (tmp2[0] >> 1);

      out[pl][i >> 3] |= (tmp2[0] & 1) << (7 - (i & 7));
    }
  }
}


void matrix_mult_z_lower_mpc_verify(uint8_t** out, uint8_t** in, int round, picnic_params_t* params) {
  // precond: affected bits must be zero, which is done by matrix_mult()
  uint8_t tmp[MAX_STATE_SIZE];
  const uint8_t* m_ptr = matrix_pointer(Z_LOWER, round, params);

  for (int i = PICNIC_SBOX_BITS; i < params->state_size << 3; i++) {
    for (int pl = 0; pl < 2; pl++) {
      for (int j = 0; j < 5; j++) {
        tmp[j] = in[pl][j] & m_ptr[(i - PICNIC_SBOX_BITS) * 5 + j];
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
        int bit_pos = 7 - ((i - 40) & 7);

        uint8_t bit = (in[pl][byte_pos] & (0x01 << bit_pos)) >> bit_pos;
        tmp[0] ^= bit;
      }

      out[pl][i >> 3] |= (tmp[0] & 1) << (7 - (i & 7));
    }
  }
}


void substitution_mpc_verify(uint8_t** state, uint8_t** tapes, uint8_t* communication, int rnds) {
  uint8_t a[2];
  uint8_t b[2];
  uint8_t c[2];

  uint8_t ab[2];
  uint8_t ac[2];
  uint8_t bc[2];

  for (int i = 0; i < PICNIC_SBOX_BITS; i += 3) {
    int bit0 = PICNIC_SBOX_BITS * rnds + i;
    int bit1 = PICNIC_SBOX_BITS * rnds + i + 1;
    int bit2 = PICNIC_SBOX_BITS * rnds + i + 2;

    int byte0 = bit0 >> 3;
    int byte1 = bit1 >> 3;
    int byte2 = bit2 >> 3;

	bit0 = 7 - (bit0 & 7);
	bit1 = 7 - (bit1 & 7);
	bit2 = 7 - (bit2 & 7);

    for (int pl = 0; pl < 2; pl++) {
      c[pl] = (state[pl][(i + 0) >> 3] >> (7 - ((i + 0) & 7))) & 1;
      b[pl] = (state[pl][(i + 1) >> 3] >> (7 - ((i + 1) & 7))) & 1;
      a[pl] = (state[pl][(i + 2) >> 3] >> (7 - ((i + 2) & 7))) & 1;
    }

    ab[0] = (a[0] & b[0]);
	ab[0] ^= (a[1] & b[0]);
	ab[0] ^= (a[0] & b[1]);
	ab[0] ^= ((tapes[0][byte0] ^ tapes[1][byte0]) >> bit0) & 1;

    bc[0] = (b[0] & c[0]);
	bc[0] ^= (b[1] & c[0]);
	bc[0] ^= (b[0] & c[1]);
	bc[0] ^= ((tapes[0][byte1] ^ tapes[1][byte1]) >> bit1) & 1;

    ac[0] = (a[0] & c[0]);
	ac[0] ^= (a[1] & c[0]);
	ac[0] ^= (a[0] & c[1]);
	ac[0] ^= ((tapes[0][byte2] ^ tapes[1][byte2]) >> bit2) & 1;

    // write interparty-communication back to the tape
    tapes[0][byte0] &= ~(1 << bit0);
    tapes[0][byte1] &= ~(1 << bit1);
    tapes[0][byte2] &= ~(1 << bit2);

    tapes[0][byte0] |= (ab[0] << bit0);
    tapes[0][byte1] |= (bc[0] << bit1);
    tapes[0][byte2] |= (ac[0] << bit2);

    ab[1] = (communication[byte0] >> bit0) & 1;
    bc[1] = (communication[byte1] >> bit1) & 1;
    ac[1] = (communication[byte2] >> bit2) & 1;

    for (int pl = 0; pl < 2; pl++) {
      state[pl][i >> 3] ^= (a[pl] ^ b[pl] ^ ab[pl]) << (7 - (i & 7));
      state[pl][(i + 1) >> 3] ^= (a[pl] ^ ac[pl]) << (7 - ((i + 1) & 7));
      state[pl][(i + 2) >> 3] ^= bc[pl] << (7 - ((i + 2) & 7));
    }
  }
}

void block_xor_inplace_mpc_verify(uint8_t** state, uint8_t** data, picnic_params_t* params) {
  for (int pl = 0; pl < 2; pl++) {
    for (int i = 0; i < params->state_size; i++) {
      state[pl][i] ^= data[pl][i];
    }
  }
}

void block_xor_const_inplace_mpc_verify(uint8_t** state, const uint8_t* data, uint8_t challenge,
                                        picnic_params_t* params) {
  if (challenge == 0) {
    for (int i = 0; i < params->state_size; i++) {
      state[0][i] ^= data[i]; // only the first party
    }
  }
  else if (challenge == 2) {
    for (int i = 0; i < params->state_size; i++) {
      state[1][i] ^= data[i]; // only the first party
    }
  }
  // else if (challenge == 1) { /* do nothing */ }
}

void generate_round_key_mpc_verify(uint8_t** out, uint8_t** keys, int round, uint8_t challenge,
                                   picnic_params_t* params) {
  const uint8_t* CN_ptr = const_pointer(CN_CONST, round, params);

  matrix_mult_mpc_verify(out, keys, PN_MATRIX, round, params);
  
  if (challenge == 0) {
    out[0][0] ^= CN_ptr[0];
    out[0][1] ^= CN_ptr[1];
    out[0][2] ^= CN_ptr[2];
    out[0][3] ^= CN_ptr[3];
  }
  else if (challenge == 2) {
    out[1][0] ^= CN_ptr[0];
    out[1][1] ^= CN_ptr[1];
    out[1][2] ^= CN_ptr[2];
    out[1][3] ^= CN_ptr[3];
  }
  // not needed for challenge = 1
}
