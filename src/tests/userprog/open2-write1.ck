# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(open2-write1) begin
(open2-write1) open "sample.txt" once
(open2-write1) open "sample.txt" again
(open2-write1) write 10 bytes to first fd
(open2-write1) end
open2-write1: exit(0)
EOF
pass;