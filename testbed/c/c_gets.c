// rule: megasast/c-gets
#include <stdio.h>
void f(char *s) {
    gets(s);
}
