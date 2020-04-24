#ifndef AES_WRAPPER_H
#define AES_WRAPPER_H

#include "picnic.h"

void encrypt_tape(uint8_t* tape, uint8_t* key, picnic_params_t* params);
void decrypt_tape(uint8_t* tape, uint8_t* key, picnic_params_t* params);

void encrypt_state(uint8_t* state, uint8_t* key, picnic_params_t* params);
void decrypt_state(uint8_t* state, uint8_t* key, picnic_params_t* params);

#endif
