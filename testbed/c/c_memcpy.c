// rule: megasast/c-memcpy
#include <string.h>
void f(char *dst, char *src) {
    memcpy(dst, src, 10);
}
