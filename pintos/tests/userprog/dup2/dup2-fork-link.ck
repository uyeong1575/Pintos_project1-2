# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([
<<'EOF',
(dup2-fork-link) open "sample.txt"
(dup2-fork-link) prime offset
(dup2-fork-link) dup2 to 30
(dup2-fork-link) child read through dup
(dup2-fork-link) wait child
dup-child: exit(0)
dup2-fork-link: exit(0)
EOF
,<<'EOF',
(dup2-fork-link) open "sample.txt"
(dup2-fork-link) prime offset
(dup2-fork-link) dup2 to 30
(dup2-fork-link) wait child
(dup2-fork-link) child read through dup
dup-child: exit(0)
dup2-fork-link: exit(0)
EOF
]);
pass;
