// Adapted from http://peeterjoot.com/2019/09/20/an-example-of-linux-glibc-symbol-versioning/

void foo2(int x, int y) {}

void foo1(int x) {}

#define V_1_2 "MYSTUFF_1.2"
#define V_1_1 "MYSTUFF_1.1"

#define SYMVER( s ) \
    __asm__(".symver " s )

SYMVER( "foo1,foo@" V_1_1 );
SYMVER( "foo2,foo@@" V_1_2 );
