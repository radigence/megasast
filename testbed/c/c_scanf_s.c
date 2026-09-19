// rule: megasast/c-scanf-s
#include <stdio.h>
void f(char *buf) {
    scanf("%s", buf);
}
