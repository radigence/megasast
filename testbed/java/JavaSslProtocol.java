// rule: megasast/java-ssl-protocol
class JavaSslProtocol {
    void f() throws Exception {
        SSLContext.getInstance("SSL");
    }
}
