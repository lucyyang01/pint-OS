# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(buffer-cache-1) begin
(buffer-cache-1) open "sample.txt" for verification
(buffer-cache-1) verified contents of "sample.txt"
(buffer-cache-1) close "sample.txt"
(buffer-cache-1) end
buffer-cache-1: exit(0)
EOF
pass;
