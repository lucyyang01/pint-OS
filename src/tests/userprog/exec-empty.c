/* Pass in empty string when calling exec syscall */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) { msg("exec(\"NOTHING\"): %d", exec("")); }