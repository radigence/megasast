// rule: megasast/c-openssl-weak-hash
void f(void *c) {
    MD5_Init(c);
}
