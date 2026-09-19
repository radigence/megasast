// rule: megasast/java-scriptengine-eval
class JavaScriptEngineEval {
    void f(javax.script.ScriptEngine e, String code) throws Exception {
        e.eval(code);
    }
}
