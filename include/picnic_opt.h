#ifndef PICNIC_OPT_H
#define PICNIC_OPT_H

#include <stdint.h>
#include <stdlib.h>

#include "sha3.h"



uint32_t picnic_opt_stream_size(picnic_params_t* params);


void picnic_opt_sign(uint8_t* stream, picnic_sk_t* sk, uint8_t* msg, uint16_t msg_len,
                     picnic_params_t* params);

void picnic_opt_stream_to_signature(uint8_t* signature, uint32_t* signature_len, uint8_t* stream,
                                    picnic_params_t* params);

uint8_t picnic_opt_verify(uint8_t* stream, uint32_t sig_len, picnic_pk_t* pk, uint8_t* msg,
                          uint16_t msg_len, picnic_params_t* params);

#endif
