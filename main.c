#include <stdio.h>
#include "include/picnic.h"

extern void test_picnic(int algo);
extern void test_picnic_opt(int algo);

void setUp(void) {}
void tearDown(void) {}

int main(int argc, char** argv) {

  /*
  3 param sets:
  PICNIC_L1_FS: 128 bit
  PICNIC_L3_FS: 192 bit
  PICNIC_L5_FS: 256 bit
  */
  int algo = PICNIC_L5_FS;

  //test according to specification
  test_picnic(algo);

  //test with our modifications
  test_picnic_opt(algo);


  return 0;
}
