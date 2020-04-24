cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(<name> C)

add_executable(picnic_opt
  src/aes_wrapper.c
  src/lowmc.c
  src/lowmc_mpc.c
  src/picnic.c
  src/picnic_hash.c
  src/picnic_opt.c
  src/picnic_opt_hash.c
  src/predefined_constants.c
  sha3/sha3.c
  aes/aes128.c
  aes/aes192.c
  aes/aes256.c
  main.c
  test_picnic.c
)
