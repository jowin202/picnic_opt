#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../include/lowmc.h"
#include "../include/lowmc_mpc.h"
#include "../include/picnic.h"
#include "../include/picnic_hash.h"

uint32_t picnic_signature_max_size(picnic_params_t* params) {
  return params->challenge_size + PICNIC_SALT_SIZE + params->mpc_rounds * params->hash_output_size +
         params->mpc_rounds * (params->tape_size + 3 * params->state_size);
}

uint32_t picnic_signature_min_size(picnic_params_t* params) {
  return params->challenge_size + PICNIC_SALT_SIZE + params->mpc_rounds * params->hash_output_size +
         params->mpc_rounds * (params->tape_size + 2 * params->state_size);
}

uint32_t picnic_signature_exact_size(picnic_params_t* params, uint8_t* challenge) {
  uint32_t size = params->challenge_size + PICNIC_SALT_SIZE +
                  params->mpc_rounds * params->hash_output_size +
                  params->mpc_rounds * (params->tape_size + 2 * params->state_size);

  for (int i = 0; i < params->mpc_rounds; i++) {
    if (((challenge[i >> 2] >> (6 - (2 * (i & 3)))) & 0x03) != 0)
      size += params->state_size;
  }

  return size;
}

void picnic_set_parameter(picnic_params_t* params, int algo) {
  params->algo = algo;
  switch (algo) {
    case PICNIC_L1_FS:
      params->state_size = 16;
      params->mpc_rounds = 219;
      params->lowmc_rounds = 20;
      params->hash_output_size = 32;
      params->tape_size = 75;
      params->challenge_size = 55;
      break;
    case PICNIC_L3_FS:
      params->state_size = 24;
      params->mpc_rounds = 329;
      params->lowmc_rounds = 30;
      params->hash_output_size = 48;
      params->tape_size = 113;
      params->challenge_size = 83;
      break;
    case PICNIC_L5_FS:
      params->state_size = 32;
      params->mpc_rounds = 438;
      params->lowmc_rounds = 38;
      params->hash_output_size = 64;
      params->tape_size = 143;
      params->challenge_size = 110;
      break;
  }
}

void picnic_keygen(picnic_pk_t* pk, picnic_sk_t* sk, picnic_params_t* params) {
  // rand_bytes(pk->plaintext, params->state_size);
  // rand_bytes(sk->key, params->state_size);
  memset(pk->plaintext, 0xF1, params->state_size);
  memset(sk->key, 0xE2, params->state_size);
  sk->key[0] = 0;
  sk->key[1] = 0;


  LowMC(pk->ciphertext, pk->plaintext, sk->key, params);

  memcpy(sk->plaintext, pk->plaintext, params->state_size);
  memcpy(sk->ciphertext, pk->ciphertext, params->state_size);
}

void picnic_sign(uint8_t* signature, uint32_t* sig_len, picnic_sk_t* sk, uint8_t* msg,
                 uint16_t msg_len, picnic_params_t* params) {

  uint16_t seed_salt_len =
      params->mpc_rounds * PICNIC_NUM_PARTIES * params->state_size + PICNIC_SALT_SIZE;
  uint8_t* seed_salt_cache = (uint8_t*) malloc(seed_salt_len * sizeof(uint8_t));
  uint8_t* salt = &seed_salt_cache[params->mpc_rounds * PICNIC_NUM_PARTIES * params->state_size];
  calcSeeds(seed_salt_cache, sk, msg, msg_len, params);

  uint16_t tapes_len = PICNIC_NUM_PARTIES * params->tape_size + 2 * params->state_size;
  uint8_t* tape_cache = (uint8_t*) malloc(tapes_len * sizeof(uint8_t));

  uint8_t* tapes[PICNIC_NUM_PARTIES];     // whole tape
  uint8_t* tapes_ptr[PICNIC_NUM_PARTIES]; // tape without input share
  tapes[0] = tape_cache;
  tapes[1] = tape_cache + params->state_size + params->tape_size;
  tapes[2] = tape_cache + 2 * params->state_size + 2 * params->tape_size;

  tapes_ptr[0] = tape_cache + params->state_size;
  tapes_ptr[1] = tape_cache + 2 * params->state_size + params->tape_size;
  tapes_ptr[2] = tape_cache + 2 * params->state_size + 2 * params->tape_size;

  uint16_t share3_len = params->mpc_rounds * params->state_size;
  uint8_t* share3_cache = (uint8_t*) malloc(share3_len * sizeof(uint8_t));

  uint8_t* shares[3];
  shares[0] = tapes[0];
  shares[1] = tapes[1];

  uint16_t output_len = PICNIC_NUM_PARTIES * params->mpc_rounds * params->state_size;
  uint8_t* output_cache = (uint8_t*) malloc(output_len * sizeof(uint8_t)); 

  uint32_t communication_len = PICNIC_NUM_PARTIES * params->mpc_rounds * params->tape_size;
  uint8_t* communication_cache = (uint8_t*) malloc(communication_len * sizeof(uint8_t)); 

  uint8_t* outputs[PICNIC_NUM_PARTIES];

  uint32_t commitment_len = PICNIC_NUM_PARTIES * params->hash_output_size * params->mpc_rounds;
  uint8_t* commitment_cache = (uint8_t*) malloc(commitment_len * sizeof(uint8_t)); 

  for (int round = 0; round < params->mpc_rounds; round++) {
    // create tapes
    uint16_t seed1_pos = (uint16_t)(PICNIC_NUM_PARTIES * round * params->state_size);
    uint16_t seed2_pos =
        (uint16_t)(PICNIC_NUM_PARTIES * round * params->state_size + params->state_size);
    uint16_t seed3_pos =
        (uint16_t)(PICNIC_NUM_PARTIES * round * params->state_size + 2 * params->state_size);

    createTape(tapes[0], &seed_salt_cache[seed1_pos], salt, round, 0, params);
    createTape(tapes[1], &seed_salt_cache[seed2_pos], salt, round, 1, params);
    createTape(tapes[2], &seed_salt_cache[seed3_pos], salt, round, 2, params);

    // prepare input shares
    uint16_t share3_offset = (uint16_t)(params->state_size * round);
    for (int i = 0; i < params->state_size; i++)
      share3_cache[share3_offset + i] = shares[0][i] ^ shares[1][i] ^ sk->key[i];
    shares[2] = share3_cache + share3_offset;

    // outputs
    outputs[0] = output_cache + (PICNIC_NUM_PARTIES * round + 0) * params->state_size;
    outputs[1] = output_cache + (PICNIC_NUM_PARTIES * round + 1) * params->state_size;
    outputs[2] = output_cache + (PICNIC_NUM_PARTIES * round + 2) * params->state_size;

    // LowMC
    LowMC_mpc(outputs, sk->plaintext, shares, tapes_ptr, params);

    // communication
    memcpy(&communication_cache[(PICNIC_NUM_PARTIES * round + 0) * params->tape_size], tapes_ptr[0],
           params->tape_size);
    memcpy(&communication_cache[(PICNIC_NUM_PARTIES * round + 1) * params->tape_size], tapes_ptr[1],
           params->tape_size);
    memcpy(&communication_cache[(PICNIC_NUM_PARTIES * round + 2) * params->tape_size], tapes_ptr[2],
           params->tape_size);

    // prepare commitments
    uint32_t commitment1_pos = (PICNIC_NUM_PARTIES * round + 0) * params->hash_output_size;
    uint32_t commitment2_pos = (PICNIC_NUM_PARTIES * round + 1) * params->hash_output_size;
    uint32_t commitment3_pos = (PICNIC_NUM_PARTIES * round + 2) * params->hash_output_size;

    commit(&commitment_cache[commitment1_pos], &seed_salt_cache[seed1_pos], shares[0],
           &communication_cache[(PICNIC_NUM_PARTIES * round + 0) * params->tape_size], outputs[0],
           params);
    commit(&commitment_cache[commitment2_pos], &seed_salt_cache[seed2_pos], shares[1],
           &communication_cache[(PICNIC_NUM_PARTIES * round + 1) * params->tape_size], outputs[1],
           params);
    commit(&commitment_cache[commitment3_pos], &seed_salt_cache[seed3_pos], shares[2],
           &communication_cache[(PICNIC_NUM_PARTIES * round + 2) * params->tape_size], outputs[2],
           params);
  }

  // challenge
  uint8_t* challenge = (uint8_t*) malloc(params->challenge_size * sizeof(uint8_t)); 
  calcChallenge(challenge, output_cache, commitment_cache, sk->ciphertext, sk->plaintext, salt, msg,
                msg_len, params);

  (*sig_len) = 0;

  memcpy(signature, challenge, params->challenge_size);
  signature += params->challenge_size;
  (*sig_len) += params->challenge_size;

  memcpy(signature, salt, PICNIC_SALT_SIZE);
  signature += PICNIC_SALT_SIZE;
  (*sig_len) += PICNIC_SALT_SIZE;

  for (int round = 0; round < params->mpc_rounds; round++) {
    int ch = (challenge[round >> 2] >> (6 - (2 * (round & 3)))) & 0x03;
    ch = (ch >> 1) | ((ch & 1) << 1);
    uint32_t commitment_pos = round * PICNIC_NUM_PARTIES * params->hash_output_size +
                              ((ch + 2) % 3) * params->hash_output_size;

    memcpy(signature, &commitment_cache[commitment_pos], params->hash_output_size);
    signature += params->hash_output_size;
    (*sig_len) += params->hash_output_size;

    uint32_t communication_pos = (PICNIC_NUM_PARTIES * round + ((ch + 1) % 3)) * params->tape_size;
    memcpy(signature, &communication_cache[communication_pos], params->tape_size);
    signature += params->tape_size;
    (*sig_len) += params->tape_size;

    uint16_t seed_pos =
        (uint16_t)(PICNIC_NUM_PARTIES * round * params->state_size + ch * params->state_size);
    memcpy(signature, &seed_salt_cache[seed_pos], params->state_size);
    signature += params->state_size;
    (*sig_len) += params->state_size;

    seed_pos = (uint16_t)(PICNIC_NUM_PARTIES * round * params->state_size +
                          ((ch + 1) % 3) * params->state_size);
    memcpy(signature, &seed_salt_cache[seed_pos], params->state_size);
    signature += params->state_size;
    (*sig_len) += params->state_size;

    uint16_t share3_pos = (uint16_t)(params->state_size * round);
    if (ch == 1 || ch == 2) {
      memcpy(signature, &share3_cache[share3_pos], params->state_size);
      signature += params->state_size;
      (*sig_len) += params->state_size;
    }
  }
	free(seed_salt_cache);
	free(tape_cache);
	free(share3_cache);
	free(output_cache);
	free(communication_cache);
	free(commitment_cache);
	free(challenge);
}

uint8_t picnic_verify(uint8_t* signature, uint32_t sig_len, picnic_pk_t* pk, uint8_t* msg,
                      uint16_t msg_len, picnic_params_t* params) {
  if (sig_len < picnic_signature_min_size(params)) //signature has to be longer than challenge for next check
    return PICNIC_SIG_INVALID;

  if (sig_len < picnic_signature_exact_size(params, signature)) //prevents seg fault if signature too short
	  return PICNIC_SIG_INVALID;


  uint8_t* challenge = signature;
  signature += params->challenge_size;
  uint8_t* salt = signature;
  signature += PICNIC_SALT_SIZE;

  uint8_t* current_commitment;
  uint8_t* current_communication;
  uint8_t** seed1_ptr = (uint8_t**) malloc(params->mpc_rounds * sizeof(uint8_t*)); 
  uint8_t** seed2_ptr = (uint8_t**) malloc(params->mpc_rounds * sizeof(uint8_t*));

  uint8_t* tape1 = (uint8_t*) malloc((params->tape_size + params->state_size) * sizeof(uint8_t));
  uint8_t* tape2 = (uint8_t*) malloc((params->tape_size + params->state_size) * sizeof(uint8_t));

  uint8_t* tapes_ptr[2];
  uint8_t* shares[2];

  uint16_t output_len = PICNIC_NUM_PARTIES * params->mpc_rounds * params->state_size;
  uint8_t* output_cache = (uint8_t*) malloc(output_len * sizeof(uint8_t)); 
  uint8_t* outputs[2];
  uint8_t* output3;

  uint32_t commitment_len = PICNIC_NUM_PARTIES * params->hash_output_size * params->mpc_rounds;
  uint8_t* commitment_cache = (uint8_t*)malloc(commitment_len * sizeof(uint8_t));

  uint8_t e0, e1, e2;

  for (int round = 0; round < params->mpc_rounds; round++) {
    current_commitment = signature;
    signature += params->hash_output_size;

    current_communication = signature;
    signature += params->tape_size;

    seed1_ptr[round] = signature;
    signature += params->state_size;

    seed2_ptr[round] = signature;
    signature += params->state_size;

    // get challenge bits from challenge string
    e0 = (challenge[round >> 2] >> (6 - 2 * (round & 3))) & 3;
    e0 = (e0 >> 1) | ((e0 & 1) << 1);
    e1 = (e0 + 1) % 3;
    e2 = (e1 + 1) % 3;
    // e0: current challenge, e1: next, e2: nextnext

    // tapes
    createTape(tape1, seed1_ptr[round], salt, round, e0, params);
    createTape(tape2, seed2_ptr[round], salt, round, e1, params);
    tapes_ptr[0] = tape1 + (e0 == 2 ? 0 : params->state_size);
    tapes_ptr[1] = tape2 + (e0 == 1 ? 0 : params->state_size);

    // input shares
    if (e0 == 0) {
      shares[0] = tape1;
      shares[1] = tape2;
    }
    else if (e0 == 1) {
      shares[0] = tape1;
      shares[1] = signature;
      signature += params->state_size;
    }
    else { // if (current_challenge == 2) {
      shares[0] = signature;
      shares[1] = tape2;
      signature += params->state_size;
    }

    // outputs
    outputs[0] = &output_cache[(PICNIC_NUM_PARTIES * round + e0) * params->state_size];
    outputs[1] = &output_cache[(PICNIC_NUM_PARTIES * round + e1) * params->state_size];
    output3 = &output_cache[(PICNIC_NUM_PARTIES * round + e2) * params->state_size];

    LowMC_mpc_verify(outputs, pk->plaintext, shares, tapes_ptr, e0, current_communication, params);

    // reconstruct 3rd output
    for (int i = 0; i < params->state_size; i++)
      output3[i] = outputs[0][i] ^ outputs[1][i] ^ pk->ciphertext[i];

    // commitments
    commit(&commitment_cache[(PICNIC_NUM_PARTIES * round + e0) * params->hash_output_size],
           seed1_ptr[round], shares[0], tapes_ptr[0], outputs[0], params);
    commit(&commitment_cache[(PICNIC_NUM_PARTIES * round + e1) * params->hash_output_size],
           seed2_ptr[round], shares[1], current_communication, outputs[1], params);
    memcpy(&commitment_cache[(PICNIC_NUM_PARTIES * round + e2) * params->hash_output_size],
           current_commitment, params->hash_output_size);
  }

  uint8_t* generated_challenge = (uint8_t*) malloc(params->challenge_size * sizeof(uint8_t)); 
  calcChallenge(generated_challenge, output_cache, commitment_cache, pk->ciphertext, pk->plaintext,
                salt, msg, msg_len, params);


  int status = memcmp(challenge, generated_challenge, params->challenge_size);

  free(seed1_ptr);
  free(seed2_ptr);
  free(tape1);
  free(tape2);
  free(output_cache);
  free(commitment_cache);
  free(generated_challenge);

  if (status == 0) {
    return PICNIC_VERIFICATION_SUCCESS;
  }

  return PICNIC_SIG_INVALID;
}
