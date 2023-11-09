/* Tests if new thread can be created, gracefully waited on, and exit */

#include "tests/lib.h"
#include "tests/main.h"
#include <pthread.h>
#include <debug.h>

void test_main(void) {
  msg("Main started.");
  tid_t tid = pthread_check_create(NULL, NULL);
  if (tid != TID_ERROR) {
    fail("TID should be TID_ERROR");
  }
  msg("Main finished.");
}
