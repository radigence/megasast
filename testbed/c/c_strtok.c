// rule: megasast/c-strtok
#include <string.h>
void f(char *s) {
    char *t = strtok(s, ",");
}
