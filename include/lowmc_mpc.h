#ifndef PICNIC_LOWMC_MPC
#define PICNIC_LOWMC_MPC


#include "picnic.h"

void LowMC_mpc(uint8_t** outputs, uint8_t* input, uint8_t** keys, uint8_t **tapes, picnic_params_t* params);

void matrix_mult_mpc(uint8_t** out, uint8_t** in, int mat_type, int round, picnic_params_t* params);
void matrix_mult_z_lower_mpc(uint8_t** out, uint8_t** in, int round, picnic_params_t* params);
void block_xor_const_inplace_mpc(uint8_t** state, const uint8_t* data, picnic_params_t* params);
void block_xor_inplace_mpc(uint8_t** state, uint8_t** data, picnic_params_t* params);
void substitution_mpc(uint8_t** state, uint8_t **tapes, int rnds);

void generate_round_key_mpc(uint8_t **out, uint8_t **keys, int round, picnic_params_t *params);


void LowMC_mpc_verify(uint8_t** outputs, uint8_t* input, uint8_t** keys, uint8_t **tapes, uint8_t challenge, uint8_t *communication, picnic_params_t* params);
void matrix_mult_mpc_verify(uint8_t** out, uint8_t** in, int LK, int round, picnic_params_t* params);
void matrix_mult_z_lower_mpc_verify(uint8_t** out, uint8_t** in, int round, picnic_params_t* params);
void substitution_mpc_verify(uint8_t** state, uint8_t **tapes, uint8_t *communication, int rnds);
void block_xor_inplace_mpc_verify(uint8_t** state, uint8_t** data, picnic_params_t* params);
void block_xor_const_inplace_mpc_verify(uint8_t** state, const uint8_t* data, uint8_t challenge, picnic_params_t* params);

void generate_round_key_mpc_verify(uint8_t **out, uint8_t **keys, int round, uint8_t challenge, picnic_params_t *params);


#endif
