/* Opens the same file twice,
   which must succeed and must return a different file descriptor
   in each case. 
   Writes to one of the files, and checks that the file position is 
   not the same for each file descriptor. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int h1 = open("sample.txt");
  int h2 = open("sample.txt");

  CHECK((h1 = open("sample.txt")) > 1, "open \"sample.txt\" once");
  CHECK((h2 = open("sample.txt")) > 1, "open \"sample.txt\" again");
  if (h1 == h2)
    fail("open() returned %d both times", h1);

  char buff[] = "test write";
  int bytes_written = write(h1, &buff, 10);

  CHECK((bytes_written = write(h1, &buff, 10)) > 0, "write 10 bytes to first fd");

  int h1_pos = tell(h1);
  int h2_pos = tell(h2);

  if (h1_pos == h2_pos) {
    fail("tell() returned the same position: %d for both file descriptors.", h1_pos);
  }
}