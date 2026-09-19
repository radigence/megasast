// rule: megasast/java-runtime-exec
class JavaRuntimeExec {
    void f(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
