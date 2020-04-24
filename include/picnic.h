#ifndef PICNIC_H
#define PICNIC_H

#include <stdint.h>
#include <stdlib.h>


#define PICNIC_NUM_PARTIES 3

#define MAX_STATE_SIZE 32
#define MAX_2_STATE_SIZE 2 * MAX_STATE_SIZE
#define MAX_3_STATE_SIZE 3 * MAX_STATE_SIZE
#define PICNIC_SHIFT_STATE_0 0
#define PICNIC_SHIFT_STATE_1 MAX_STATE_SIZE
#define PICNIC_SHIFT_STATE_2 2*MAX_STATE_SIZE

#define PICNIC_SALT_SIZE 32U
#define PICNIC_MAX_CHALLENGE 110

#define PICNIC_SIG_INVALID 0
#define PICNIC_VERIFICATION_SUCCESS 1

#define PICNIC_NUM_SBOXES 10
#define PICNIC_SBOX_BITS 3 * PICNIC_NUM_SBOXES

enum { UNKONWN_VERSION, PICNIC_L1_FS, PICNIC_L1_UR, PICNIC_L3_FS, PICNIC_L3_UR, PICNIC_L5_FS, PICNIC_L5_UR };


enum { LINEAR_MATRIX, KEY_MATRIX, PL_MATRIX, PN_MATRIX, RC_CONST, CL_CONST, CN_CONST, Z_MATRIX, Z_UPPER, Z_LOWER, Z_LAST };

typedef struct  {
  int algo;
  uint16_t state_size;
  uint16_t mpc_rounds;
  uint16_t lowmc_rounds;
  uint16_t hash_output_size;
  uint16_t challenge_size;
  uint8_t tape_size;
} picnic_params_t;

typedef struct {
  uint8_t plaintext[MAX_STATE_SIZE];
  uint8_t ciphertext[MAX_STATE_SIZE];
} picnic_pk_t;

typedef struct {
  uint8_t key[MAX_STATE_SIZE];
  uint8_t plaintext[MAX_STATE_SIZE];
  uint8_t ciphertext[MAX_STATE_SIZE];
} picnic_sk_t;


uint32_t picnic_signature_max_size(picnic_params_t* params);
uint32_t picnic_signature_min_size(picnic_params_t* params);
uint32_t picnic_signature_exact_size(picnic_params_t* params, uint8_t* challenge);

void picnic_set_parameter(picnic_params_t* params, int algo);
void picnic_keygen(picnic_pk_t* pk, picnic_sk_t* sk, picnic_params_t* params);

void picnic_sign(uint8_t* signature, uint32_t* sig_len, picnic_sk_t* sk, uint8_t* msg,
                 uint16_t msg_len, picnic_params_t* params);
uint8_t picnic_verify(uint8_t* signature, uint32_t sig_len, picnic_pk_t* pk, uint8_t* msg,
                      uint16_t msg_len, picnic_params_t* params);

#endif

