// rule: megasast/c-mktemp
void f(char *tmpl) {
    char *t = mktemp(tmpl);
}
