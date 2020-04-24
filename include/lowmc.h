#ifndef PICNIC_LOWMC
#define PICNIC_LOWMC

#include "picnic.h"


void LowMC(uint8_t* out, uint8_t* in, uint8_t* key, picnic_params_t* params);

void matrix_mult(uint8_t* out, uint8_t* in, int mat_type, int round, picnic_params_t* params);
void substitution(uint8_t* state);
void block_xor_inplace(uint8_t* state, const uint8_t* data, picnic_params_t* params);
void block_xor(uint8_t* out, uint8_t* in1, uint8_t* in2, picnic_params_t* params);

void generate_round_key(uint8_t *out, uint8_t *key, int round, picnic_params_t *params);

void matrix_mult_z_lower(uint8_t* out, uint8_t* in, int round, picnic_params_t* params);

#endif
