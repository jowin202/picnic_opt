#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../include/picnic.h"
#include "../include/sha3.h"

void calcSeeds(uint8_t* out, picnic_sk_t* sk, uint8_t* msg, uint16_t msg_len,
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
  shake_out(&sha3, out,
            params->mpc_rounds * PICNIC_NUM_PARTIES * params->state_size + PICNIC_SALT_SIZE);
}

void createTape(uint8_t* out, uint8_t* seed, uint8_t* salt, int rnd, int party,
                picnic_params_t* params) {

  sha3_ctx_t sha3;
  uint8_t hashbyte = 0x02;
  uint16_t out_len = params->tape_size + (party == 2 ? 0 : params->state_size);
  uint8_t* buffer = (uint8_t*) malloc(params->hash_output_size * sizeof(uint8_t));
  

  if (params->algo == PICNIC_L1_FS) {
    shake128_init(&sha3);
  }
  else {
    shake256_init(&sha3);
  }


  shake_update(&sha3, &hashbyte, 1);
  shake_update(&sha3, seed, params->state_size);
  shake_xof(&sha3);
  shake_out(&sha3, buffer, params->hash_output_size);

  if (params->algo == PICNIC_L1_FS)
    shake128_init(&sha3);
  else
    shake256_init(&sha3);

  shake_update(&sha3, buffer, params->hash_output_size);
  shake_update(&sha3, salt, PICNIC_SALT_SIZE);

  uint8_t bytes[2];
  bytes[0] = (rnd)&0xFF;
  bytes[1] = (rnd >> 8) & 0xFF;
  shake_update(&sha3, bytes, 2);

  bytes[0] = (party)&0xFF;
  bytes[1] = (party >> 8) & 0xFF;
  shake_update(&sha3, bytes, 2);

  bytes[0] = (out_len)&0xFF;
  bytes[1] = (out_len >> 8) & 0xFF;
  shake_update(&sha3, bytes, 2);

  shake_xof(&sha3);
  shake_out(&sha3, out, out_len);

  if (params->algo == PICNIC_L3_FS || params->algo == PICNIC_L5_FS)
    out[out_len - 1] &= 0xF0; // last 4 bits must be 0 in L3 and L5, communication bits

  free(buffer);
}

void commit(uint8_t* out, uint8_t* seed, uint8_t* share, uint8_t* communication, uint8_t* output,
            picnic_params_t* params) {

  uint8_t hashbyte = 0x04;
  uint8_t *buffer = (uint8_t*) malloc(params->hash_output_size * sizeof(uint8_t));
  sha3_ctx_t sha3;

  if (params->algo == PICNIC_L1_FS)
    shake128_init(&sha3);
  else
    shake256_init(&sha3);

  shake_update(&sha3, &hashbyte, 1);
  shake_update(&sha3, seed, params->state_size);
  shake_xof(&sha3);
  hashbyte = 0x00;

  shake_out(&sha3, buffer, params->hash_output_size);

  if (params->algo == PICNIC_L1_FS)
    shake128_init(&sha3);
  else
    shake256_init(&sha3);

  shake_update(&sha3, &hashbyte, 1);
  shake_update(&sha3, buffer, params->hash_output_size);
  shake_update(&sha3, share, params->state_size);
  shake_update(&sha3, communication, params->tape_size);
  shake_update(&sha3, output, params->state_size);
  shake_xof(&sha3);

  shake_out(&sha3, out, params->hash_output_size);
  
  free(buffer);
}

void calcChallenge(uint8_t* out, uint8_t* outputs, uint8_t* commitments, uint8_t* ciphertext,
                   uint8_t* plaintext, uint8_t* salt, uint8_t* msg, int msg_len,
                   picnic_params_t* params) {

  uint8_t hashbyte = 0x01;
  sha3_ctx_t sha3;
  uint16_t bits_needed = 0;
  uint16_t buffer_max = params->hash_output_size;
  uint8_t* buffer = (uint8_t*) malloc(buffer_max * sizeof(uint8_t));

  if (params->algo == PICNIC_L1_FS) {
    bits_needed = 438;
    shake128_init(&sha3);
  }
  else if (params->algo == PICNIC_L3_FS) {
    bits_needed = 658;
    shake256_init(&sha3);
  }
  else if (params->algo == PICNIC_L5_FS) {
    bits_needed = 876;
    shake256_init(&sha3);
  }

  shake_update(&sha3, &hashbyte, 1);
  shake_update(&sha3, outputs, PICNIC_NUM_PARTIES * params->state_size * params->mpc_rounds);
  shake_update(&sha3, commitments,
               PICNIC_NUM_PARTIES * params->hash_output_size * params->mpc_rounds);

  shake_update(&sha3, ciphertext, params->state_size);
  shake_update(&sha3, plaintext, params->state_size);
  shake_update(&sha3, salt, PICNIC_SALT_SIZE);
  shake_update(&sha3, msg, msg_len);
  shake_xof(&sha3);
  shake_out(&sha3, buffer, buffer_max);

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
      shake128_init(&sha3);
    else
      shake256_init(&sha3);

    shake_update(&sha3, &hashbyte, 1);
    shake_update(&sha3, buffer, buffer_max);
    shake_xof(&sha3);

    shake_out(&sha3, buffer, buffer_max);
  }

  free(buffer);
}
