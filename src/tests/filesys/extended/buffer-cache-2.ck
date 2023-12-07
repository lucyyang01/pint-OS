# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(buffer-cache-2) begin
(buffer-cache-2) create "test.txt"
(buffer-cache-2) open "test.txt"
(buffer-cache-2) end
buffer-cache-2: exit(0)
EOF
pass;
