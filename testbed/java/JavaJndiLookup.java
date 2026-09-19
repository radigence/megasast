// rule: megasast/java-jndi-lookup
class JavaJndiLookup {
    void f(javax.naming.Context ctx, String name) throws Exception {
        ctx.lookup(name);
    }
}
