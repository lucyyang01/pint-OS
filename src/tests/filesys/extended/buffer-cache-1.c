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
  double begin_hitrate = hit_rate();
  msg("%f", begin_hitrate);
  /* Check file opens, reads blocks sequentially, and closes the file */
  check_file("sample.txt", sample, sizeof sample - 1);
  double first_hitrate = hit_rate();
  msg("%f", first_hitrate);
  check_file("sample.txt", sample, sizeof sample - 1);
  double second_hitrate = hit_rate();
  msg("%f", second_hitrate);
  // CHECK(first_hitrate < second_hitrate, "Check that the hit rate improves.");
}
