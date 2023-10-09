# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF', <<'EOF']);
(write-stdout) begin
(write-stdout) end
write-stout: exit(0)
EOF
(write-stdout) begin
write-stdout: exit(0)
EOF
pass;
