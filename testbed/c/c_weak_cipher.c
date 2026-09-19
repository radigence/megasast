// rule: megasast/c-weak-cipher
void f(void *k, void *ks) {
    DES_set_key(k, ks);
}
