#include "../include/aes128.h"
#include "../include/aes192.h"
#include "../include/aes256.h"

#include "../include/picnic.h"

void encrypt_tape(uint8_t* tape, uint8_t* key, picnic_params_t* params)
{
	if (params->algo == PICNIC_L1_FS) {
		aes128_context ctx;
        aes128_init(&ctx, key);
		aes128_encrypt_ecb(&ctx, tape);
		aes128_encrypt_ecb(&ctx, tape + 16);
		aes128_encrypt_ecb(&ctx, tape + 32);
		aes128_encrypt_ecb(&ctx, tape + 48);
		aes128_encrypt_ecb(&ctx, tape + 59);
	}
	else if (params->algo == PICNIC_L3_FS)
	{
        aes192_context ctx;
        aes192_init(&ctx, key);
        aes192_encrypt_ecb(&ctx, tape);
        aes192_encrypt_ecb(&ctx, tape + 16);
        aes192_encrypt_ecb(&ctx, tape + 32);
        aes192_encrypt_ecb(&ctx, tape + 48);
        aes192_encrypt_ecb(&ctx, tape + 64);
        aes192_encrypt_ecb(&ctx, tape + 80);
        aes192_encrypt_ecb(&ctx, tape + 96);
	}
	else //if (params->algo == PICNIC_L5_FS)
	{
        aes256_context ctx;
        aes256_init(&ctx, key);
        aes256_encrypt_ecb(&ctx, tape);
        aes256_encrypt_ecb(&ctx, tape + 16);
        aes256_encrypt_ecb(&ctx, tape + 32);
        aes256_encrypt_ecb(&ctx, tape + 48);
        aes256_encrypt_ecb(&ctx, tape + 64);
        aes256_encrypt_ecb(&ctx, tape + 80);
        aes256_encrypt_ecb(&ctx, tape + 96);
        aes256_encrypt_ecb(&ctx, tape + 112);
        aes256_encrypt_ecb(&ctx, tape + 127);
	}
}

void decrypt_tape(uint8_t* tape, uint8_t* key, picnic_params_t* params)
{
	if (params->algo == PICNIC_L1_FS) {
		aes128_context ctx;
		aes128_init(&ctx, key);
		aes128_decrypt_ecb(&ctx, tape + 59);
		aes128_decrypt_ecb(&ctx, tape + 48);
		aes128_decrypt_ecb(&ctx, tape + 32);
		aes128_decrypt_ecb(&ctx, tape + 16);
		aes128_decrypt_ecb(&ctx, tape);
	}
	else if (params->algo == PICNIC_L3_FS)
	{
		aes192_context ctx;
		aes192_init(&ctx, key);
		aes192_decrypt_ecb(&ctx, tape + 96);
		aes192_decrypt_ecb(&ctx, tape + 80);
		aes192_decrypt_ecb(&ctx, tape + 64);
		aes192_decrypt_ecb(&ctx, tape + 48);
		aes192_decrypt_ecb(&ctx, tape + 32);
		aes192_decrypt_ecb(&ctx, tape + 16);
		aes192_decrypt_ecb(&ctx, tape);
	}
	else //if (params->algo == PICNIC_L5_FS)
	{
        aes256_context ctx;
        aes256_init(&ctx, key);
        aes256_decrypt_ecb(&ctx, tape + 127);
        aes256_decrypt_ecb(&ctx, tape + 112);
        aes256_decrypt_ecb(&ctx, tape + 96);
        aes256_decrypt_ecb(&ctx, tape + 80);
        aes256_decrypt_ecb(&ctx, tape + 64);
        aes256_decrypt_ecb(&ctx, tape + 48);
        aes256_decrypt_ecb(&ctx, tape + 32);
        aes256_decrypt_ecb(&ctx, tape + 16);
        aes256_decrypt_ecb(&ctx, tape);
	}
}

void encrypt_state(uint8_t* state, uint8_t* key, picnic_params_t* params)
{
	if (params->algo == PICNIC_L1_FS) {
		aes128_context ctx;
		aes128_init(&ctx, key);
		aes128_encrypt_ecb(&ctx, state);
	}
	else if (params->algo == PICNIC_L3_FS)
	{
		aes192_context ctx;
		aes192_init(&ctx, key);
		aes192_encrypt_ecb(&ctx, state);
	}
	else //if (params->algo == PICNIC_L5_FS)
        {
			aes256_context ctx;
			aes256_init(&ctx, key);
			aes256_encrypt_ecb(&ctx, state);
			aes256_encrypt_ecb(&ctx, state + 16);
	}
}

void decrypt_state(uint8_t* state, uint8_t* key, picnic_params_t* params)
{
	if (params->algo == PICNIC_L1_FS) {
		aes128_context ctx;
		aes128_init(&ctx, key);
		aes128_decrypt_ecb(&ctx, state);
	}
	else if (params->algo == PICNIC_L3_FS)
	{
          aes192_context ctx;
          aes192_init(&ctx, key);
          aes192_decrypt_ecb(&ctx, state);
	}
	else //if (params->algo == PICNIC_L5_FS)
	{
          aes256_context ctx;
          aes256_init(&ctx, key);
          aes256_decrypt_ecb(&ctx, state);
          aes256_decrypt_ecb(&ctx, state + 16);
	}
}
