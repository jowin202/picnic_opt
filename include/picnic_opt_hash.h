#ifndef PICNIC_OPT_HASH
#define PICNIC_OPT_HASH

#include "picnic.h"
#include "sha3.h"

void calcSalt_opt(uint8_t* out, picnic_sk_t* sk, uint8_t* msg, uint16_t msg_len,
                  picnic_params_t* params);

//calc seeds 
sha3_ctx_t init_seeds_opt(picnic_sk_t* sk, uint8_t* msg, uint16_t msg_len, picnic_params_t *params);
void get_seeds_opt(uint8_t* out, sha3_ctx_t* ctx, picnic_params_t* params);

//challenge 
sha3_ctx_t init_challenge_opt(picnic_params_t* params);
void update_challenge_opt(sha3_ctx_t* ctx, uint8_t* outputs, uint8_t* commitments,
                          picnic_params_t* params);
void finalize_challenge_opt(uint8_t* out, sha3_ctx_t* ctx, uint8_t* ciphertext, uint8_t* plaintext,
                            uint8_t* salt, uint8_t* msg, int msg_len, picnic_params_t* params);
#endif
