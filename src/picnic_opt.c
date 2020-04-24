#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../include/aes_wrapper.h"
#include "../include/lowmc.h"
#include "../include/lowmc_mpc.h"
#include "../include/picnic.h"
#include "../include/picnic_opt.h"
#include "../include/picnic_hash.h"
#include "../include/picnic_opt_hash.h"
#include "../include/sha3.h"

uint32_t picnic_opt_stream_size(picnic_params_t* params) {
  return params->challenge_size                                    // challenge
         + PICNIC_SALT_SIZE                                        // salt
         + params->mpc_rounds * (                                  // for all rounds
                                    3 * params->hash_output_size + // 3 commitments
                                    3 * params->tape_size +        // 3 communications
                                    3 * params->state_size         // 2 seeds + 3rd party output
                                );
}

void picnic_opt_sign(uint8_t* stream, picnic_sk_t* sk, uint8_t* msg, uint16_t msg_len,
                     picnic_params_t* params) {

  // salt
  uint8_t salt[PICNIC_SALT_SIZE];
  calcSalt_opt(salt, sk, msg, msg_len, params);
  memcpy(stream, salt, PICNIC_SALT_SIZE);
  stream += PICNIC_SALT_SIZE;

  // seeds
  sha3_ctx_t seed_ctx = init_seeds_opt(sk, msg, msg_len, params);
  uint16_t seeds_len = PICNIC_NUM_PARTIES * params->state_size;
  uint8_t* seed_cache = (uint8_t*) malloc(seeds_len * sizeof(uint8_t));
  uint8_t* seed[3];
  seed[0] = seed_cache;
  seed[1] = seed_cache + params->state_size;
  seed[2] = seed_cache + 2 * params->state_size;

  // tapes
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

  uint8_t* share3 = (uint8_t*) malloc(params->state_size * sizeof(uint8_t));
  uint8_t* shares[3];
  shares[0] = tapes[0];
  shares[1] = tapes[1];
  shares[2] = share3;

  // outputs
  uint16_t output_len = PICNIC_NUM_PARTIES * params->state_size; // one round
  uint8_t* output_cache = (uint8_t*) malloc(output_len * sizeof(uint8_t));
  uint8_t* outputs[PICNIC_NUM_PARTIES];
  outputs[0] = output_cache + 0 * params->state_size;
  outputs[1] = output_cache + 1 * params->state_size;
  outputs[2] = output_cache + 2 * params->state_size;

  // challenge
  sha3_ctx_t challenge_ctx = init_challenge_opt(params);

  for (int round = 0; round < params->mpc_rounds; round++) {
    // seeds
    get_seeds_opt(seed_cache, &seed_ctx, params);

    // create tapes
    createTape(tapes[0], seed[0], salt, round, 0, params);
    createTape(tapes[1], seed[1], salt, round, 1, params);
    createTape(tapes[2], seed[2], salt, round, 2, params);

    // prepare input shares
    for (int i = 0; i < params->state_size; i++)
      share3[i] = shares[0][i] ^ shares[1][i] ^ sk->key[i];

    // LowMC
    LowMC_mpc(outputs, sk->plaintext, shares, tapes_ptr, params);

    // commitments
    uint8_t* commitment_offset = stream;
    commit(stream, seed[0], shares[0], tapes_ptr[0], outputs[0], params);
    stream += params->hash_output_size;
    commit(stream, seed[1], shares[1], tapes_ptr[1], outputs[1], params);
    stream += params->hash_output_size;
    commit(stream, seed[2], shares[2], tapes_ptr[2], outputs[2], params);
    stream += params->hash_output_size;

    // communication
    encrypt_tape(tapes_ptr[0], seed[0], params);
    encrypt_tape(tapes_ptr[1], seed[1], params);
    encrypt_tape(tapes_ptr[2], seed[2], params);

    memcpy(stream, tapes_ptr[0], params->tape_size);
    stream += params->tape_size;
    memcpy(stream, tapes_ptr[1], params->tape_size);
    stream += params->tape_size;
    memcpy(stream, tapes_ptr[2], params->tape_size);
    stream += params->tape_size;

    // share3
    encrypt_state(share3, seed[2], params);
    memcpy(stream, share3, params->state_size);
    stream += params->state_size;

    update_challenge_opt(&challenge_ctx, output_cache, commitment_offset, params);
  }

  // challenge
  uint8_t* challenge = (uint8_t*) malloc(params->challenge_size * sizeof(uint8_t));
  finalize_challenge_opt(challenge, &challenge_ctx, sk->ciphertext, sk->plaintext, salt, msg,
                         msg_len, params);

  memcpy(stream, challenge, params->challenge_size);
  stream += params->challenge_size;

  // seeds
  seed_ctx = init_seeds_opt(sk, msg, msg_len, params);

  for (int round = 0; round < params->mpc_rounds; round++) {
    int ch = (challenge[round >> 2] >> (6 - (2 * (round & 3)))) & 0x03;
    ch = (ch >> 1) | ((ch & 1) << 1);

    get_seeds_opt(seed_cache, &seed_ctx, params);

    memcpy(stream, seed[ch], params->state_size);
    stream += params->state_size;

    memcpy(stream, seed[(ch + 1) % 3], params->state_size);
    stream += params->state_size;
  }

  free(seed_cache);
  free(tape_cache);
  free(share3);
  free(output_cache);
  free(challenge);
}

void picnic_opt_stream_to_signature(uint8_t* signature, uint32_t* signature_len, uint8_t* stream,
                                    picnic_params_t* params) {

  uint8_t* salt = stream;
  stream += PICNIC_SALT_SIZE;

  uint8_t* address = stream;
  stream += params->mpc_rounds *
            (params->state_size + 3 * params->hash_output_size + 3 * params->tape_size);

  uint8_t* challenge = stream;
  stream += params->challenge_size;

  uint8_t* seeds = stream;

  // init Signature
  *signature_len = PICNIC_SALT_SIZE + params->challenge_size;
  memcpy(signature, challenge, params->challenge_size);
  signature += params->challenge_size;
  memcpy(signature, salt, PICNIC_SALT_SIZE);
  signature += PICNIC_SALT_SIZE;

  for (int round = 0; round < params->mpc_rounds; round++) {
    int ch = (challenge[round >> 2] >> (6 - (2 * (round & 3)))) & 0x03;
    ch = (ch >> 1) | ((ch & 1) << 1);

    // add commitment
    memcpy(signature, address + ((ch + 2) % 3) * params->hash_output_size,
           params->hash_output_size);
    address += 3 * params->hash_output_size;
    signature += params->hash_output_size;
    *signature_len += params->hash_output_size;

    // add communication
    memcpy(signature, address + ((ch + 1) % 3) * params->tape_size, params->tape_size);
    decrypt_tape(signature, seeds + params->state_size, params);
    address += 3 * params->tape_size;
    signature += params->tape_size;
    *signature_len += params->tape_size;

    // add seeds
    memcpy(signature, seeds, 2 * params->state_size); // shift seeds later
    signature += 2 * params->state_size;
    *signature_len += 2 * params->state_size;

    // add additional share
    if (ch != 0)
	{
      memcpy(signature, address, params->state_size);

      decrypt_state(signature, seeds + (2 - ch) * params->state_size, params);
      signature += params->state_size;
      *signature_len += params->state_size;
    }

    seeds += 2 * params->state_size;
    address += params->state_size; //share3 is always present
  }
}

uint8_t picnic_opt_verify(uint8_t* signature, uint32_t sig_len, picnic_pk_t* pk, uint8_t* msg,
                          uint16_t msg_len, picnic_params_t* params) {
  if (sig_len <
      picnic_signature_min_size(params)) // signature has to be longer than challenge for next check
    return PICNIC_SIG_INVALID;

  if (sig_len <
      picnic_signature_exact_size(params, signature)) // prevents seg fault if signature too short
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

  uint16_t output_len = PICNIC_NUM_PARTIES * params->state_size;
  uint8_t* output_cache = (uint8_t*) malloc(output_len * sizeof(uint8_t));
  uint8_t* outputs[2];
  uint8_t* output3;

  uint32_t commitment_len = PICNIC_NUM_PARTIES * params->hash_output_size;
  uint8_t* commitment_cache = (uint8_t*)malloc(commitment_len * sizeof(uint8_t));

  uint8_t e0, e1, e2;


  // challenge
  sha3_ctx_t challenge_ctx = init_challenge_opt(params);

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
    outputs[0] = &output_cache[e0 * params->state_size];
    outputs[1] = &output_cache[e1 * params->state_size];
    output3 = &output_cache[e2 * params->state_size];

    LowMC_mpc_verify(outputs, pk->plaintext, shares, tapes_ptr, e0, current_communication, params);

    // reconstruct 3rd output
    for (int i = 0; i < params->state_size; i++)
      output3[i] = outputs[0][i] ^ outputs[1][i] ^ pk->ciphertext[i];

    // commitments
    commit(&commitment_cache[e0 * params->hash_output_size], seed1_ptr[round], shares[0],
           tapes_ptr[0], outputs[0], params);
    commit(&commitment_cache[e1 * params->hash_output_size], seed2_ptr[round], shares[1],
           current_communication, outputs[1], params);
    memcpy(&commitment_cache[e2 * params->hash_output_size], current_commitment,
           params->hash_output_size);

    update_challenge_opt(&challenge_ctx, output_cache, commitment_cache, params);
  }

  uint8_t* generated_challenge = (uint8_t*) malloc(params->challenge_size * sizeof(uint8_t));
  finalize_challenge_opt(generated_challenge, &challenge_ctx, pk->ciphertext, pk->plaintext, salt,
                         msg, msg_len, params);

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
