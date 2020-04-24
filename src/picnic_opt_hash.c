#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../include/picnic.h"
#include "../include/picnic_opt_hash.h"
#include "../include/sha3.h"

void calcSalt_opt(uint8_t* out, picnic_sk_t* sk, uint8_t* msg, uint16_t msg_len,
                   picnic_params_t* params) {
  //change this, it's inefficient
  //independed for verification
  sha3_ctx_t sha3;
  if (params->algo == PICNIC_L1_FS)
    shake128_init(&sha3);
  else
    shake256_init(&sha3);

  uint8_t bytes[2];
  bytes[0] = (params->state_size << 3) & 0xFF; // state_size required in bits
  bytes[1] = (params->state_size >> 5) & 0xFF; //

  shake_update(&sha3, sk->key, params->state_size);
  shake_update(&sha3, msg, msg_len);
  shake_update(&sha3, sk->ciphertext, params->state_size);
  shake_update(&sha3, sk->plaintext, params->state_size);
  shake_update(&sha3, bytes, 2);
  shake_xof(&sha3);

  for (int i = 0; i < params->mpc_rounds * PICNIC_NUM_PARTIES * params->state_size; i += 32)
	shake_out(&sha3, out, 32);

  if (params->algo == PICNIC_L1_FS)
  {
    memcpy(out, out + 16, 16);
    uint8_t tmp[32];
    shake_out(&sha3, tmp, 32);
    memcpy(out + 16, tmp, 16);
  }
  else if (params->algo == PICNIC_L3_FS)
  {
    memmove(out, out + 8, 24);
    uint8_t tmp[32];
    shake_out(&sha3, tmp, 32);
    memcpy(out + 24, tmp, 8);
  }
  else
  {
    shake_out(&sha3, out, 32);
  }

}


sha3_ctx_t init_seeds_opt(picnic_sk_t* sk, uint8_t* msg, uint16_t msg_len,
                          picnic_params_t* params) {
  sha3_ctx_t sha3;
  if (params->algo == PICNIC_L1_FS)
    shake128_init(&sha3);
  else
    shake256_init(&sha3);

  uint8_t bytes[2];
  bytes[0] = (params->state_size << 3) & 0xFF; // state_size required in bits
  bytes[1] = (params->state_size >> 5) & 0xFF; //

  shake_update(&sha3, sk->key, params->state_size);
  shake_update(&sha3, msg, msg_len);
  shake_update(&sha3, sk->ciphertext, params->state_size);
  shake_update(&sha3, sk->plaintext, params->state_size);
  shake_update(&sha3, bytes, 2);
  shake_xof(&sha3);

  return sha3;
}


void get_seeds_opt(uint8_t* out, sha3_ctx_t* ctx, picnic_params_t* params)
{
  shake_out(ctx, out, params->state_size * 3);
}



sha3_ctx_t init_challenge_opt(picnic_params_t* params) {

  uint8_t hashbyte = 0x01;
  sha3_ctx_t sha3;

  if (params->algo == PICNIC_L1_FS) 
    shake128_init(&sha3);
  else 
    shake256_init(&sha3);


  shake_update(&sha3, &hashbyte, 1);
  return sha3;
}

void update_challenge_opt(sha3_ctx_t* ctx, uint8_t* outputs, uint8_t* commitments, picnic_params_t *params) {
  shake_update(ctx, outputs, PICNIC_NUM_PARTIES * params->state_size); 
  shake_update(ctx, commitments, PICNIC_NUM_PARTIES * params->hash_output_size);
}

void finalize_challenge_opt(uint8_t* out, sha3_ctx_t* ctx, uint8_t* ciphertext, uint8_t* plaintext,
                            uint8_t* salt, uint8_t* msg, int msg_len, picnic_params_t* params) {

  uint16_t bits_needed = 0;
  uint16_t buffer_max = 0;

  if (params->algo == PICNIC_L1_FS) {
    bits_needed = 438;
    buffer_max = 32;
  }
  else if (params->algo == PICNIC_L3_FS) {
    bits_needed = 658;
    buffer_max = 48;
  }
  else if (params->algo == PICNIC_L5_FS) {
    bits_needed = 876;
    buffer_max = 64;
  }
  uint8_t* buffer = (uint8_t*) malloc(buffer_max * sizeof(uint8_t));


  shake_update(ctx, ciphertext, params->state_size);
  shake_update(ctx, plaintext, params->state_size);
  shake_update(ctx, salt, PICNIC_SALT_SIZE);
  shake_update(ctx, msg, msg_len);
  shake_xof(ctx);
  shake_out(ctx, buffer, buffer_max);

  int pos = 0;
  int offset = 0;
  uint8_t current_byte = 0;
  int byte_pos = 8;
  int tmp;

  while (bits_needed > 0) {
    while (bits_needed > 0 && pos < buffer_max) {
      for (int bits_chosen = 6; bits_chosen >= 0; bits_chosen -= 2) {
        tmp = (buffer[pos] >> bits_chosen) & 0x03;
        tmp = ((tmp & 1) << 1) | ((tmp >> 1) & 1);
        if (tmp < 3 && pos < buffer_max && bits_needed > 0) {
          byte_pos -= 2;
          bits_needed -= 2;
          current_byte |= (tmp << byte_pos);
          if (byte_pos == 0 || bits_needed == 0) {
            byte_pos = 8;
            out[offset++] = current_byte;
            current_byte = 0;
          }
        }
      }
      pos++;
    }
    pos = 0;

    if (params->algo == PICNIC_L1_FS)
      shake128_init(ctx);
    else
      shake256_init(ctx);

    uint8_t hashbyte = 0x01;
    shake_update(ctx, &hashbyte, 1);
    shake_update(ctx, buffer, buffer_max);
    shake_xof(ctx);

    shake_out(ctx, buffer, buffer_max);
  }
  free(buffer);
}
