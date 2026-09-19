// rule: megasast/java-sql-concat
class JavaSqlConcat {
    void f() throws Exception {
        stmt.executeQuery("select " + x);
    }
}
