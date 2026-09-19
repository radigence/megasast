// rule: megasast/c-setuid
#include <unistd.h>
void f() {
    setuid(0);
}
