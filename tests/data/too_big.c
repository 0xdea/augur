// Object file with a function too big for Hex-Rays to decompile (`MAX_FUNCSIZE`
// is 64 KB, and `too_big` is about twice that) and a small function, each
// referencing its own string, used to test string uses that are skipped.
// Built with: clang -target x86_64-linux-gnu -O0 -c -o too_big too_big.c
extern int puts(const char *s);

#define S1 sink = 1;
#define S10 S1 S1 S1 S1 S1 S1 S1 S1 S1 S1
#define S100 S10 S10 S10 S10 S10 S10 S10 S10 S10 S10
#define S1000 S100 S100 S100 S100 S100 S100 S100 S100 S100 S100
#define S10000 S1000 S1000 S1000 S1000 S1000 S1000 S1000 S1000 S1000 S1000

void too_big(void) {
    // A volatile local keeps every store, and needs no relocation.
    volatile int sink;
    puts("used in a function too big to decompile");
    S10000 S10000
}

int small(void) {
    return puts("used in a function that decompiles");
}
