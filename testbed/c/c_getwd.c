// rule: megasast/c-getwd
#include <unistd.h>
void f(char *b) {
    getwd(b);
}
