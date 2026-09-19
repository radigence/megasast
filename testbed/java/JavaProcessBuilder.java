// rule: megasast/java-processbuilder
class JavaProcessBuilder {
    void f() throws Exception {
        new ProcessBuilder("ls").start();
    }
}
