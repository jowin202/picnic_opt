#include "include/lowmc.h"
#include "include/picnic.h"
#include "include/picnic_hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_picnic(int algo) {

  printf("Picnic reference implementation:\n");

  // define message as 500 bytes 0x01
  uint16_t msg_len = 500;
  uint8_t msg[500];
  memset(msg, 0x01, msg_len);

  // set parameter
  picnic_params_t params;
  picnic_set_parameter(&params, algo);
  
  // Key Generation
  picnic_pk_t pk;
  picnic_sk_t sk;
  picnic_keygen(&pk, &sk, &params); 


  // Test Sign
  uint32_t max_sig_size = picnic_signature_max_size(&params);
  uint32_t sig_len = 0;
  uint8_t *signature = malloc(max_sig_size * sizeof(uint8_t));

  if (signature != NULL)
  {
	//printf("Max signature length: %d\n", max_sig_size);
  }
  else
  {
    printf("Error: could not allocate signature.\n");
	return;
  }

  picnic_sign(signature, &sig_len, &sk, msg, msg_len, &params);

  uint8_t status = picnic_verify(signature, sig_len, &pk, msg, msg_len, &params);
  if (status == PICNIC_VERIFICATION_SUCCESS)
  {
	  printf("Verification success\n");
	  //Do something with the signature
  }

  free(signature);
}


void test_picnic_opt(int algo) {

	printf("Picnic optimized implementation:\n");

	// define message as 500 bytes 0x01
	uint16_t msg_len = 500;
	uint8_t msg[500];
	memset(msg, 0x01, msg_len);

	// set parameter
	picnic_params_t params;
	picnic_set_parameter(&params, algo);

	// Key Generation
	picnic_pk_t pk;
	picnic_sk_t sk;
	picnic_keygen(&pk, &sk, &params); // no changes in key generation

	// Test Sign
	uint32_t stream_size = picnic_opt_stream_size(&params);
	uint32_t max_signature_size = picnic_signature_max_size(&params);
	uint32_t sig_len = 0;
	uint8_t* signature_stream = malloc(stream_size * sizeof(uint8_t));
	uint8_t* signature = malloc(max_signature_size * sizeof(uint8_t));

	if (signature_stream != NULL || signature != NULL) {
		printf("Stream size: %d\n", stream_size);
	}
	else {
		printf("Error: could not allocate signature or signature stream.\n");
		return;
	}

	// create a signature stream 
	// simulates the transfer from a constrained device where the secret key is stored to a host system
	picnic_opt_sign(signature_stream, &sk, msg, msg_len, &params);

	// create actual signature from signature stream
	picnic_opt_stream_to_signature(signature, &sig_len, signature_stream, &params);

	uint8_t status =
		picnic_opt_verify(signature, sig_len, &pk, msg, msg_len, &params);

	if (status == PICNIC_VERIFICATION_SUCCESS)
	{
		printf("Verification success\n");
		//Do something with the signature
	}

	free(signature);
	free(signature_stream);
}

