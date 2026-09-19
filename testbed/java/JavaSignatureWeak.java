// rule: megasast/java-signature-weak
class JavaSignatureWeak {
    void f() throws Exception {
        Signature.getInstance("MD5withRSA");
    }
}
