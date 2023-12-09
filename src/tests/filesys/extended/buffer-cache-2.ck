# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(buffer-cache-2) begin
(buffer-cache-2) open "test.txt"
(buffer-cache-2) open "test.txt" for verification
(buffer-cache-2) verified contents of "test.txt"
(buffer-cache-2) close "test.txt"
(buffer-cache-2) Order of 128
(buffer-cache-2) end
buffer-cache-2: exit(0)
EOF
pass;
