// rule: megasast/c-sprintf
#include <stdio.h>
void f(char *s) {
    sprintf(s, "x");
}
