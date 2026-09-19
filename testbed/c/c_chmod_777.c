// rule: megasast/c-chmod-777
#include <sys/stat.h>
void f(char *p) {
    chmod(p, 0777);
}
