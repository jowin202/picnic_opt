#include "../include/picnic.h"
#include "../include/predefined_constants.h"
#include <stdint.h>
#include <stdlib.h>

const uint8_t* matrix_pointer(int mat_type, int round, picnic_params_t* params) {
  if (mat_type == PL_MATRIX && params->algo == PICNIC_L1_FS) {
    return PL_L1;
  }
  else if (mat_type == PL_MATRIX && params->algo == PICNIC_L3_FS) {
    return PL_L3;
  }
  else if (mat_type == PL_MATRIX && params->algo == PICNIC_L5_FS) {
    return PL_L5;
  }
  else if (mat_type == PN_MATRIX && params->algo == PICNIC_L1_FS) {
    return PN_L1 + PICNIC_SBOX_BITS * round * params->state_size;
  }
  else if (mat_type == PN_MATRIX && params->algo == PICNIC_L3_FS) {
    return PN_L3 + PICNIC_SBOX_BITS * round * params->state_size;
  }
  else if (mat_type == PN_MATRIX && params->algo == PICNIC_L5_FS) {
    return PN_L5 + PICNIC_SBOX_BITS * round * params->state_size;
  }
  else if (mat_type == Z_UPPER && params->algo == PICNIC_L1_FS) {
    return Z_upper_L1 + PICNIC_SBOX_BITS * round * params->state_size;
  }
  else if (mat_type == Z_LOWER && params->algo == PICNIC_L1_FS) {
	return Z_lower_L1 + (8 * params->state_size - PICNIC_SBOX_BITS) * round * 5;
  }
  else if (mat_type == Z_LAST && params->algo == PICNIC_L1_FS) {
    return Z_last_L1;
  }
  else if (mat_type == Z_UPPER && params->algo == PICNIC_L3_FS) {
    return Z_upper_L3 + PICNIC_SBOX_BITS * round * params->state_size;
  }
  else if (mat_type == Z_LOWER && params->algo == PICNIC_L3_FS) {
    return Z_lower_L3 + (8 * params->state_size - PICNIC_SBOX_BITS) * round * 5;
  }
  else if (mat_type == Z_LAST && params->algo == PICNIC_L3_FS) {
    return Z_last_L3;
  }
  else if (mat_type == Z_UPPER && params->algo == PICNIC_L5_FS) {
    return Z_upper_L5 + PICNIC_SBOX_BITS * round * params->state_size;
  }
  else if (mat_type == Z_LOWER && params->algo == PICNIC_L5_FS) {
    return Z_lower_L5 + (8 * params->state_size - PICNIC_SBOX_BITS) * round * 5;
  }
  else if (mat_type == Z_LAST && params->algo == PICNIC_L5_FS) {
    return Z_last_L5;
  }
  else
    return 0;
}

const uint8_t* const_pointer(int const_type, int round, picnic_params_t* params) {
  if (const_type == CL_CONST && params->algo == PICNIC_L1_FS) {
    return CL_L1;
  }
  else if (const_type == CL_CONST && params->algo == PICNIC_L3_FS) {
    return CL_L3;
  }
  else if (const_type == CL_CONST && params->algo == PICNIC_L5_FS) {
    return CL_L5;
  }
  else if (const_type == CN_CONST && params->algo == PICNIC_L1_FS) {
    return CN_L1 + 4 * round;
  }
  else if (const_type == CN_CONST && params->algo == PICNIC_L3_FS) {
    return CN_L3 + 4 * round;
  }
  else if (const_type == CN_CONST && params->algo == PICNIC_L5_FS) {
    return CN_L5 + 4 * round;
  }
  else
    return 0;
}
