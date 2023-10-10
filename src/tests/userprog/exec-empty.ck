# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF', <<'EOF', <<'EOF', <<'EOF']);
(exec-empty) begin
load: no-such-file: open failed
(exec-empty) exec("no-such-file"): -1
(exec-empty) end
exec-empty: exit(0)
EOF
(exec-empty) begin
(exec-empty) exec("NOTHING"): -1
(exec-empty) end
exec-empty: exit(0)
EOF
(exec-empty) begin
load: no-such-file: open failed
no-such-file: exit(-1)
(exec-empty) exec("no-such-file"): -1
(exec-empty) end
exec-empty: exit(0)
EOF
(exec-empty) begin
load: no-such-file: open failed
(exec-empty) exec("no-such-file"): -1
no-such-file: exit(-1)
(exec-empty) end
exec-empty: exit(0)
EOF
pass;