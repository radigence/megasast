"""Generate the synthetic testbed corpus: one vulnerable file per megasast rule.

Usage (from repo root):
    python scripts/generate_testbed.py

Writes testbed/<lang>/<file> + testbed/manifest.json + testbed/README.md.
Every snippet below is a proven true positive (mirrors
tests/test_rule_coverage.py and the tests/fixtures samples). Each file
carries a header comment with its expected rule id so the corpus is
self-documenting: `megasast scan testbed --format text`.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTBED = ROOT / "testbed"

# (relative path, expected rule id(s), source)
CASES: list[tuple[str, list[str], str]] = [
    # ---- Python (22) ----
    ("python/py_eval.py", ["megasast/py-eval"],
     '# rule: megasast/py-eval\neval(user_input)\n'),
    ("python/py_exec.py", ["megasast/py-exec"],
     '# rule: megasast/py-exec\nexec(user_input)\n'),
    ("python/py_os_system.py", ["megasast/py-os-system"],
     '# rule: megasast/py-os-system\nimport os\nos.system("ls " + user_input)\n'),
    ("python/py_pickle_load.py", ["megasast/py-pickle-load"],
     '# rule: megasast/py-pickle-load\nimport pickle\nwith open("data.pkl", "rb") as f:\n    obj = pickle.load(f)\n'),
    ("python/py_pickle_loads.py", ["megasast/py-pickle-loads"],
     '# rule: megasast/py-pickle-loads\nimport pickle\nobj = pickle.loads(data)\n'),
    ("python/py_marshal_load.py", ["megasast/py-marshal-load"],
     '# rule: megasast/py-marshal-load\nimport marshal\nobj = marshal.loads(data)\n'),
    ("python/py_yaml_load.py", ["megasast/py-yaml-load"],
     '# rule: megasast/py-yaml-load\nimport yaml\nobj = yaml.load(stream)\n'),
    ("python/py_subprocess_shell.py", ["megasast/py-subprocess-shell"],
     '# rule: megasast/py-subprocess-shell\nimport subprocess\nsubprocess.run(cmd, shell=True)\n'),
    ("python/py_asyncio_subprocess_shell.py", ["megasast/py-asyncio-subprocess-shell"],
     '# rule: megasast/py-asyncio-subprocess-shell\nimport asyncio\nasyncio.create_subprocess_shell(cmd)\n'),
    ("python/py_requests_no_verify.py", ["megasast/py-requests-no-verify"],
     '# rule: megasast/py-requests-no-verify\nimport requests\nrequests.get(url, verify=False)\n'),
    ("python/py_ssl_unverified_context.py", ["megasast/py-ssl-unverified-context"],
     '# rule: megasast/py-ssl-unverified-context\nimport ssl\nssl._create_unverified_context()\n'),
    ("python/py_hashlib_md5.py", ["megasast/py-hashlib-md5"],
     '# rule: megasast/py-hashlib-md5\nimport hashlib\nhashlib.md5(b"data")\n'),
    ("python/py_hashlib_sha1.py", ["megasast/py-hashlib-sha1"],
     '# rule: megasast/py-hashlib-sha1\nimport hashlib\nhashlib.sha1(b"data")\n'),
    ("python/py_mktemp.py", ["megasast/py-mktemp"],
     '# rule: megasast/py-mktemp\nimport tempfile\ntempfile.mktemp()\n'),
    ("python/py_os_mktemp.py", ["megasast/py-os-mktemp"],
     '# rule: megasast/py-os-mktemp\nimport os\nos.mktemp()\n'),
    ("python/py_chmod_777.py", ["megasast/py-chmod-777"],
     '# rule: megasast/py-chmod-777\nimport os\nos.chmod(path, 0o777)\n'),
    ("python/py_plaintext_protocol.py", ["megasast/py-plaintext-protocol"],
     '# rule: megasast/py-plaintext-protocol\nimport telnetlib\n'),
    ("python/py_simple_http_server.py", ["megasast/py-simple-http-server"],
     '# rule: megasast/py-simple-http-server\nfrom http.server import BaseHTTPRequestHandler\nclass H(BaseHTTPRequestHandler):\n    pass\n'),
    ("python/py_jinja2_autoescape.py", ["megasast/py-jinja2-autoescape"],
     '# rule: megasast/py-jinja2-autoescape\nEnvironment(loader, autoescape=False)\n'),
    ("python/py_django_mark_safe.py", ["megasast/py-django-mark-safe"],
     '# rule: megasast/py-django-mark-safe\nfrom django.utils.safestring import mark_safe\nmark_safe(user_input)\n'),
    ("python/py_sql_fstring.py", ["megasast/py-sql-fstring"],
     '# rule: megasast/py-sql-fstring\ncursor.execute(f"select * from t where a={user_input}")\n'),
    ("python/py_flask_debug.py", ["megasast/py-flask-debug"],
     '# rule: megasast/py-flask-debug\napp.run(debug=True)\n'),
    # ---- JavaScript (14) ----
    ("javascript/js_eval.js", ["megasast/js-eval"],
     '// rule: megasast/js-eval\neval(userInput);\n'),
    ("javascript/js_new_function.js", ["megasast/js-new-function"],
     '// rule: megasast/js-new-function\nvar f = new Function("a", "return a");\n'),
    ("javascript/js_innerhtml.js", ["megasast/js-innerhtml"],
     '// rule: megasast/js-innerhtml\nel.innerHTML = userInput;\n'),
    ("javascript/js_outerhtml.js", ["megasast/js-outerhtml"],
     '// rule: megasast/js-outerhtml\nel.outerHTML = userInput;\n'),
    ("javascript/js_insert_adjacent_html.js", ["megasast/js-insert-adjacent-html"],
     '// rule: megasast/js-insert-adjacent-html\nel.insertAdjacentHTML("beforeend", html);\n'),
    ("javascript/js_child_process_exec.js", ["megasast/js-child-process-exec"],
     '// rule: megasast/js-child-process-exec\nchild_process.exec(cmd);\n'),
    ("javascript/js_child_process_exec_sync.js", ["megasast/js-child-process-exec-sync"],
     '// rule: megasast/js-child-process-exec-sync\nchild_process.execSync(cmd);\n'),
    ("javascript/js_document_write.js", ["megasast/js-document-write"],
     '// rule: megasast/js-document-write\ndocument.write(content);\n'),
    ("javascript/js_vm_runincontext.js", ["megasast/js-vm-runincontext"],
     '// rule: megasast/js-vm-runincontext\nconst vm = require("vm");\nvm.runInNewContext(code);\n'),
    ("javascript/js_spawn_shell.js", ["megasast/js-spawn-shell"],
     '// rule: megasast/js-spawn-shell\nchild_process.spawn(cmd, { shell: true });\n'),
    ("javascript/js_reject_unauthorized.js", ["megasast/js-reject-unauthorized"],
     '// rule: megasast/js-reject-unauthorized\nhttps.request({ rejectUnauthorized: false });\n'),
    ("javascript/js_localstorage_secret.js", ["megasast/js-localstorage-secret"],
     '// rule: megasast/js-localstorage-secret\nlocalStorage.setItem("authToken", token);\n'),
    ("javascript/js_crypto_weak_hash.js", ["megasast/js-crypto-weak-hash"],
     '// rule: megasast/js-crypto-weak-hash\ncrypto.createHash("md5");\n'),
    ("javascript/js_settimeout_string.js", ["megasast/js-settimeout-string"],
     '// rule: megasast/js-settimeout-string\nsetTimeout("alert(1)", 100);\n'),
    # ---- Java (12) ----
    ("java/JavaRuntimeExec.java", ["megasast/java-runtime-exec"],
     '// rule: megasast/java-runtime-exec\nclass JavaRuntimeExec {\n    void f(String cmd) throws Exception {\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n'),
    ("java/JavaProcessBuilder.java", ["megasast/java-processbuilder"],
     '// rule: megasast/java-processbuilder\nclass JavaProcessBuilder {\n    void f() throws Exception {\n        new ProcessBuilder("ls").start();\n    }\n}\n'),
    ("java/JavaReadObject.java", ["megasast/java-readobject"],
     '// rule: megasast/java-readobject\nclass JavaReadObject {\n    void f(java.io.ObjectInputStream ois) throws Exception {\n        ois.readObject();\n    }\n}\n'),
    ("java/JavaScriptEngineEval.java", ["megasast/java-scriptengine-eval"],
     '// rule: megasast/java-scriptengine-eval\nclass JavaScriptEngineEval {\n    void f(javax.script.ScriptEngine e, String code) throws Exception {\n        e.eval(code);\n    }\n}\n'),
    ("java/JavaCipherWeak.java", ["megasast/java-cipher-weak"],
     '// rule: megasast/java-cipher-weak\nclass JavaCipherWeak {\n    void f() throws Exception {\n        Cipher.getInstance("DES");\n    }\n}\n'),
    ("java/JavaSignatureWeak.java", ["megasast/java-signature-weak"],
     '// rule: megasast/java-signature-weak\nclass JavaSignatureWeak {\n    void f() throws Exception {\n        Signature.getInstance("MD5withRSA");\n    }\n}\n'),
    ("java/JavaSqlConcat.java", ["megasast/java-sql-concat"],
     '// rule: megasast/java-sql-concat\nclass JavaSqlConcat {\n    void f() throws Exception {\n        stmt.executeQuery("select " + x);\n    }\n}\n'),
    ("java/JavaXxe.java", ["megasast/java-xxe"],
     '// rule: megasast/java-xxe\nclass JavaXxe {\n    void f() throws Exception {\n        TransformerFactory.newInstance();\n    }\n}\n'),
    ("java/JavaJndiLookup.java", ["megasast/java-jndi-lookup"],
     '// rule: megasast/java-jndi-lookup\nclass JavaJndiLookup {\n    void f(javax.naming.Context ctx, String name) throws Exception {\n        ctx.lookup(name);\n    }\n}\n'),
    ("java/JavaMessageDigestMd5.java", ["megasast/java-message-digest-md5"],
     '// rule: megasast/java-message-digest-md5\nclass JavaMessageDigestMd5 {\n    void f() throws Exception {\n        MessageDigest.getInstance("MD5");\n    }\n}\n'),
    ("java/JavaMessageDigestSha1.java", ["megasast/java-message-digest-sha1"],
     '// rule: megasast/java-message-digest-sha1\nclass JavaMessageDigestSha1 {\n    void f() throws Exception {\n        MessageDigest.getInstance("SHA-1");\n    }\n}\n'),
    ("java/JavaSslProtocol.java", ["megasast/java-ssl-protocol"],
     '// rule: megasast/java-ssl-protocol\nclass JavaSslProtocol {\n    void f() throws Exception {\n        SSLContext.getInstance("SSL");\n    }\n}\n'),
    # ---- C (16) ----
    ("c/c_system.c", ["megasast/c-system"],
     '// rule: megasast/c-system\n#include <stdlib.h>\nvoid f(char *cmd) {\n    system(cmd);\n}\n'),
    ("c/c_popen.c", ["megasast/c-popen"],
     '// rule: megasast/c-popen\n#include <stdio.h>\nint main() {\n    FILE *f = popen("ls", "r");\n    return 0;\n}\n'),
    ("c/c_strcpy.c", ["megasast/c-strcpy"],
     '// rule: megasast/c-strcpy\n#include <string.h>\nvoid f(char *dst, char *src) {\n    strcpy(dst, src);\n}\n'),
    ("c/c_gets.c", ["megasast/c-gets"],
     '// rule: megasast/c-gets\n#include <stdio.h>\nvoid f(char *s) {\n    gets(s);\n}\n'),
    ("c/c_sprintf.c", ["megasast/c-sprintf"],
     '// rule: megasast/c-sprintf\n#include <stdio.h>\nvoid f(char *s) {\n    sprintf(s, "x");\n}\n'),
    ("c/c_strcat.c", ["megasast/c-strcat"],
     '// rule: megasast/c-strcat\n#include <string.h>\nvoid f(char *dst, char *src) {\n    strcat(dst, src);\n}\n'),
    ("c/c_scanf_s.c", ["megasast/c-scanf-s"],
     '// rule: megasast/c-scanf-s\n#include <stdio.h>\nvoid f(char *buf) {\n    scanf("%s", buf);\n}\n'),
    ("c/c_memcpy.c", ["megasast/c-memcpy"],
     '// rule: megasast/c-memcpy\n#include <string.h>\nvoid f(char *dst, char *src) {\n    memcpy(dst, src, 10);\n}\n'),
    ("c/c_openssl_weak_hash.c", ["megasast/c-openssl-weak-hash"],
     '// rule: megasast/c-openssl-weak-hash\nvoid f(void *c) {\n    MD5_Init(c);\n}\n'),
    ("c/c_weak_cipher.c", ["megasast/c-weak-cipher"],
     '// rule: megasast/c-weak-cipher\nvoid f(void *k, void *ks) {\n    DES_set_key(k, ks);\n}\n'),
    ("c/c_mktemp.c", ["megasast/c-mktemp"],
     '// rule: megasast/c-mktemp\nvoid f(char *tmpl) {\n    char *t = mktemp(tmpl);\n}\n'),
    ("c/c_setuid.c", ["megasast/c-setuid"],
     '// rule: megasast/c-setuid\n#include <unistd.h>\nvoid f() {\n    setuid(0);\n}\n'),
    ("c/c_chmod_777.c", ["megasast/c-chmod-777"],
     '// rule: megasast/c-chmod-777\n#include <sys/stat.h>\nvoid f(char *p) {\n    chmod(p, 0777);\n}\n'),
    ("c/c_getwd.c", ["megasast/c-getwd"],
     '// rule: megasast/c-getwd\n#include <unistd.h>\nvoid f(char *b) {\n    getwd(b);\n}\n'),
    ("c/c_strtok.c", ["megasast/c-strtok"],
     '// rule: megasast/c-strtok\n#include <string.h>\nvoid f(char *s) {\n    char *t = strtok(s, ",");\n}\n'),
    ("c/c_atoi.c", ["megasast/c-atoi"],
     '// rule: megasast/c-atoi\n#include <stdlib.h>\nvoid f(char *s) {\n    int n = atoi(s);\n}\n'),
    # ---- Go (9) ----
    ("go/go_exec_cmd.go", ["megasast/go-exec-cmd"],
     '// rule: megasast/go-exec-cmd\npackage sample\n\nimport "os/exec"\n\nfunc f() {\n    _ = exec.Command("/bin/ls", "-l")\n}\n'),
    # NOTE: invoking a shell via exec.Command also matches the generic
    # go-exec-cmd rule, so this file is expected to fire twice.
    ("go/go_exec_shell.go", ["megasast/go-exec-cmd", "megasast/go-exec-shell"],
     '// rule: megasast/go-exec-shell (+ megasast/go-exec-cmd)\npackage sample\n\nimport "os/exec"\n\nfunc f() {\n    _ = exec.Command("sh", "-c", cmd)\n}\n'),
    ("go/go_insecure_skip_verify.go", ["megasast/go-insecure-skip-verify"],
     '// rule: megasast/go-insecure-skip-verify\npackage sample\n\nimport "crypto/tls"\n\nvar _ = &tls.Config{InsecureSkipVerify: true}\n'),
    ("go/go_gob_decode.go", ["megasast/go-gob-decode"],
     '// rule: megasast/go-gob-decode\npackage sample\n\nimport "encoding/gob"\n\nfunc f() {\n    _ = gob.NewDecoder(r).Decode(&v)\n}\n'),
    ("go/go_sql_sprintf.go", ["megasast/go-sql-sprintf"],
     '// rule: megasast/go-sql-sprintf\npackage sample\n\nimport "fmt"\n\nfunc f() {\n    _ = db.Query(fmt.Sprintf("select %s", x))\n}\n'),
    ("go/go_crypto_md5.go", ["megasast/go-crypto-md5"],
     '// rule: megasast/go-crypto-md5\npackage sample\n\nimport "crypto/md5"\n'),
    ("go/go_crypto_sha1.go", ["megasast/go-crypto-sha1"],
     '// rule: megasast/go-crypto-sha1\npackage sample\n\nimport "crypto/sha1"\n'),
    ("go/go_weak_cipher_import.go", ["megasast/go-weak-cipher-import"],
     '// rule: megasast/go-weak-cipher-import\npackage sample\n\nimport "crypto/des"\n'),
    ("go/go_unsafe_import.go", ["megasast/go-unsafe-import"],
     '// rule: megasast/go-unsafe-import\npackage sample\n\nimport "unsafe"\n'),
    # ---- PHP (19) ----
    ("php/php_eval.php", ["megasast/php-eval"],
     '<?php // rule: megasast/php-eval\neval($_GET["x"]);\n?>'),
    ("php/php_exec.php", ["megasast/php-exec"],
     '<?php // rule: megasast/php-exec\nexec($c);\n?>'),
    ("php/php_system.php", ["megasast/php-system"],
     '<?php // rule: megasast/php-system\nsystem($c);\n?>'),
    ("php/php_passthru.php", ["megasast/php-passthru"],
     '<?php // rule: megasast/php-passthru\npassthru($c);\n?>'),
    ("php/php_proc_open.php", ["megasast/php-proc-open"],
     '<?php // rule: megasast/php-proc-open\nproc_open($c, $d, $p);\n?>'),
    ("php/php_popen.php", ["megasast/php-popen"],
     '<?php // rule: megasast/php-popen\n$h = popen($c, "r");\n?>'),
    ("php/php_shell_exec.php", ["megasast/php-shell-exec"],
     '<?php // rule: megasast/php-shell-exec\nshell_exec($c);\n?>'),
    ("php/php_assert.php", ["megasast/php-assert"],
     "<?php // rule: megasast/php-assert\nassert('phpinfo()');\n?>"),
    ("php/php_create_function.php", ["megasast/php-create-function"],
     "<?php // rule: megasast/php-create-function\ncreate_function('', $c);\n?>"),
    ("php/php_preg_replace_e.php", ["megasast/php-preg-replace-e"],
     "<?php // rule: megasast/php-preg-replace-e\npreg_replace('/x/e', $r, $s);\n?>"),
    ("php/php_include_variable.php", ["megasast/php-include-variable"],
     '<?php // rule: megasast/php-include-variable\ninclude $x;\n?>'),
    ("php/php_request_superglobal.php", ["megasast/php-request-superglobal"],
     '<?php // rule: megasast/php-request-superglobal\necho $_REQUEST["x"];\n?>'),
    ("php/php_unserialize.php", ["megasast/php-unserialize"],
     '<?php // rule: megasast/php-unserialize\nunserialize($data);\n?>'),
    ("php/php_curl_no_verify.php", ["megasast/php-curl-no-verify"],
     '<?php // rule: megasast/php-curl-no-verify\ncurl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n?>'),
    ("php/php_sql_concat.php", ["megasast/php-sql-concat"],
     '<?php // rule: megasast/php-sql-concat\n$db->query("a" . $b);\n?>'),
    ("php/php_mcrypt.php", ["megasast/php-mcrypt"],
     '<?php // rule: megasast/php-mcrypt\nmcrypt_encrypt(MCRYPT_RIJNDAEL_256, $k, $d, MCRYPT_MODE_CBC);\n?>'),
    ("php/php_md5.php", ["megasast/php-md5"],
     '<?php // rule: megasast/php-md5\nmd5($value);\n?>'),
    ("php/php_sha1.php", ["megasast/php-sha1"],
     '<?php // rule: megasast/php-sha1\nsha1($value);\n?>'),
    ("php/php_extract.php", ["megasast/php-extract"],
     '<?php // rule: megasast/php-extract\nextract($_POST);\n?>'),
    # ---- Rust (8) ----
    ("rust/rust_command.rs", ["megasast/rust-command"],
     '// rule: megasast/rust-command\nuse std::process::Command;\n\nfn f() {\n    let _ = Command::new("ls");\n}\n'),
    ("rust/rust_danger_accept_invalid.rs", ["megasast/rust-danger-accept-invalid"],
     '// rule: megasast/rust-danger-accept-invalid\nfn f() {\n    Client::builder().danger_accept_invalid_certs(true);\n}\n'),
    ("rust/rust_unsafe.rs", ["megasast/rust-unsafe"],
     '// rule: megasast/rust-unsafe\nfn f(p: *const u8) {\n    unsafe {\n        std::ptr::read(p);\n    }\n}\n'),
    ("rust/rust_transmute.rs", ["megasast/rust-transmute"],
     '// rule: megasast/rust-transmute\nfn f(raw: u32) {\n    let value = std::mem::transmute(raw);\n}\n'),
    ("rust/rust_from_utf8_unchecked.rs", ["megasast/rust-from-utf8-unchecked"],
     '// rule: megasast/rust-from-utf8-unchecked\nfn f(v: Vec<u8>) {\n    String::from_utf8_unchecked(v);\n}\n'),
    ("rust/rust_mem_zeroed.rs", ["megasast/rust-mem-zeroed"],
     '// rule: megasast/rust-mem-zeroed\nfn f() {\n    let x: u8 = mem::zeroed();\n}\n'),
    ("rust/rust_slice_raw_parts.rs", ["megasast/rust-slice-raw-parts"],
     '// rule: megasast/rust-slice-raw-parts\nfn f(p: *mut u8) {\n    Vec::from_raw_parts(p, 1, 1);\n}\n'),
    ("rust/rust_weak_hash_import.rs", ["megasast/rust-weak-hash-import"],
     '// rule: megasast/rust-weak-hash-import\nuse md5::Digest;\n\nfn f() {}\n'),
    # ---- Cross-language secrets (3, python representative) ----
    ("secrets/aws_access_key.py", ["megasast/aws-access-key"],
     '# rule: megasast/aws-access-key\nk = "AKIAIOSFODNN7EXAMPLE"\n'),
    ("secrets/hardcoded_secret.py", ["megasast/hardcoded-secret"],
     '# rule: megasast/hardcoded-secret\npassword = "secret123value"\n'),
    ("secrets/insecure_rand.py", ["megasast/insecure-rand"],
     '# rule: megasast/insecure-rand\nimport random\ntoken = random.choice(items)\n'),
]

README = """# megasast testbed

Synthetic vulnerable-by-design corpus: **one file per rule** (103 files,
103 rules). Each file contains a minimal true positive and a header comment
with the expected rule id(s).

Intentionally vulnerable — do not deploy, do not copy patterns into
production code.

## Run

```bash
megasast scan testbed --format text
megasast scan testbed -o report.sarif --format sarif
```

Expected: every file fires its documented rule. `go/go_exec_shell.go`
fires twice (`go-exec-cmd` + `go-exec-shell`) by design, so 103 files
yield 104 findings. `manifest.json` records the per-file expectation.

## Regenerate

```bash
python scripts/generate_testbed.py
```
"""


def main() -> None:
    TESTBED.mkdir(exist_ok=True)
    manifest: list[dict] = []
    for rel, rules, source in CASES:
        path = TESTBED / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        manifest.append({"file": rel, "expected_rules": rules})
    (TESTBED / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    (TESTBED / "README.md").write_text(README, encoding="utf-8")
    print(f"wrote {len(CASES)} files + manifest.json + README.md to {TESTBED}")


if __name__ == "__main__":
    main()
