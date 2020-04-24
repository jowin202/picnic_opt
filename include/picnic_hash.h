#ifndef PICNIC_HASH
#define PICNIC_HASH

#include "picnic.h"

//precalc all seeds and salt
//42080 bytes in L5
void calcSeeds(uint8_t* out, picnic_sk_t *sk, uint8_t* msg, uint16_t msg_len, picnic_params_t* params);

//generating pseudorandom tape according to standard
//void createTape(uint8_t* out, uint8_t* seeds, uint8_t *salt, int rnd, int tape_mask, picnic_params_t* params);
void createTape(uint8_t* out, uint8_t* seed, uint8_t *salt, int rnd, int party, picnic_params_t* params);

//calc commitment
void commit(uint8_t* out, uint8_t* seed, uint8_t* share, uint8_t* communication, uint8_t* output,
            picnic_params_t* params);

//challenge 
void calcChallenge(uint8_t* out, uint8_t* outputs, uint8_t* commitments, uint8_t* ciphertext,
                   uint8_t* plaintext, uint8_t* salt, uint8_t* msg, int msg_len,
                   picnic_params_t* params);

#endif
