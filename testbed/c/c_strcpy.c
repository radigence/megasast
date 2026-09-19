// rule: megasast/c-strcpy
#include <string.h>
void f(char *dst, char *src) {
    strcpy(dst, src);
}
