// rule: megasast/java-message-digest-sha1
class JavaMessageDigestSha1 {
    void f() throws Exception {
        MessageDigest.getInstance("SHA-1");
    }
}
