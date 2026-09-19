// rule: megasast/c-strcat
#include <string.h>
void f(char *dst, char *src) {
    strcat(dst, src);
}
