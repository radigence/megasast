// rule: megasast/c-system
#include <stdlib.h>
void f(char *cmd) {
    system(cmd);
}
