// rule: megasast/java-xxe
class JavaXxe {
    void f() throws Exception {
        TransformerFactory.newInstance();
    }
}
