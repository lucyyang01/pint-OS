# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(create-fail) begin
(create-fail) Main started.
create-fail: exit(1)
EOF
pass;
