// rule: megasast/c-popen
#include <stdio.h>
int main() {
    FILE *f = popen("ls", "r");
    return 0;
}
