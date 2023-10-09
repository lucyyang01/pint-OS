/* Tests that we can write to stdout. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  char buf = 123;
  write(1, &buf, 3);
}