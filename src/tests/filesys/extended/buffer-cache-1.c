/* Tests buffer cache. */
/*
Test your buffer cache’s effectiveness by measuring its cache hit rate. 
First, reset the buffer cache. Next, open a file and read it sequentially, 
to determine the cache hit rate for a cold cache. 
Then, close it, re-open it, and read it sequentially again, to make sure that the cache hit rate improves.
*/

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
#include "tests/userprog/sample.inc"

void test_main(void) {
  cache_flush();
  float h1 = cache_hits();
  float a1 = cache_accesses();

  float begin_hitrate = h1 / a1;
  CHECK(begin_hitrate <= 1, "Check that hitrate is less than 0");
  /* Check file opens, reads blocks sequentially, and closes the file */
  check_file("sample.txt", sample, sizeof sample - 1);
  float h2 = cache_hits();
  float a2 = cache_accesses();
  double first_hitrate = h2 / a2;
  CHECK(first_hitrate <= 1, "Check that hitrate is less than 0");
  check_file("sample.txt", sample, sizeof sample - 1);
  float h3 = cache_hits();
  float a3 = cache_accesses();
  double second_hitrate = h3 / a3;
  CHECK(second_hitrate <= 1, "Check that hitrate is less than 0");
  CHECK(first_hitrate < second_hitrate, "Check that the hit rate improves.");
}
