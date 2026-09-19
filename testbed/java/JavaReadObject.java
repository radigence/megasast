// rule: megasast/java-readobject
class JavaReadObject {
    void f(java.io.ObjectInputStream ois) throws Exception {
        ois.readObject();
    }
}
