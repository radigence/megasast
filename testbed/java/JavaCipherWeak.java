// rule: megasast/java-cipher-weak
class JavaCipherWeak {
    void f() throws Exception {
        Cipher.getInstance("DES");
    }
}
