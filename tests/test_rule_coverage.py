import pytest

from megasast.engine import scan_file
from megasast.parser import TreeSitterParser


@pytest.mark.parametrize(
    ("filename", "source", "expected_rule"),
    [
        ("sample.py", "import ssl\nssl._create_unverified_context()\n", "megasast/py-ssl-unverified-context"),
        ("sample.py", "import hashlib\nhashlib.md5(b'data')\n", "megasast/py-hashlib-md5"),
        ("sample.py", "import hashlib\nhashlib.sha1(b'data')\n", "megasast/py-hashlib-sha1"),
        ("sample.py", "import tempfile\ntempfile.mktemp()\n", "megasast/py-mktemp"),
        ("sample.js", "child_process.execSync(command);\n", "megasast/js-child-process-exec-sync"),
        ("sample.js", "document.write(content);\n", "megasast/js-document-write"),
        ("Sample.java", "class Sample { void f() { MessageDigest.getInstance(\"MD5\"); } }\n", "megasast/java-message-digest-md5"),
        ("Sample.java", "class Sample { void f() { MessageDigest.getInstance(\"SHA-1\"); } }\n", "megasast/java-message-digest-sha1"),
        ("sample.go", "package sample\nimport \"crypto/md5\"\n", "megasast/go-crypto-md5"),
        ("sample.go", "package sample\nimport \"crypto/sha1\"\n", "megasast/go-crypto-sha1"),
        ("sample.c", "void f(char *s) { gets(s); sprintf(s, \"x\"); strcat(s, \"x\"); }\n", "megasast/c-gets"),
        ("sample.c", "void f(char *s) { sprintf(s, \"x\"); }\n", "megasast/c-sprintf"),
        ("sample.c", "void f(char *s) { strcat(s, \"x\"); }\n", "megasast/c-strcat"),
        ("sample.php", "<?php md5($value); sha1($value); ?>\n", "megasast/php-md5"),
        ("sample.php", "<?php sha1($value); ?>\n", "megasast/php-sha1"),
        ("sample.py", "import pickle\npickle.loads(data)\n", "megasast/py-pickle-loads"),
        ("sample.py", "import marshal\nmarshal.loads(data)\n", "megasast/py-marshal-load"),
        ("sample.py", "import asyncio\nasyncio.create_subprocess_shell(cmd)\n", "megasast/py-asyncio-subprocess-shell"),
        ("sample.py", "import requests\nrequests.get(url, verify=False)\n", "megasast/py-requests-no-verify"),
        ("sample.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n", "megasast/py-subprocess-shell"),
        ("sample.js", "const vm = require(\"vm\");\nvm.runInNewContext(code);\n", "megasast/js-vm-runincontext"),
        ("sample.js", "child_process.spawn(cmd, { shell: true });\n", "megasast/js-spawn-shell"),
        ("sample.js", "spawn(cmd, { shell: true });\n", "megasast/js-spawn-shell"),
        ("sample.js", "https.request({ rejectUnauthorized: false });\n", "megasast/js-reject-unauthorized"),
        ("sample.ts", "https.request({ rejectUnauthorized: false });\n", "megasast/js-reject-unauthorized"),
        ("Sample.java", "class S { void f(ObjectInputStream ois) throws Exception { ois.readObject(); } }\n", "megasast/java-readobject"),
        ("Sample.java", "class S { void f(ScriptEngine e) throws Exception { e.eval(code); } }\n", "megasast/java-scriptengine-eval"),
        ("Sample.java", "class S { void f() throws Exception { new ProcessBuilder(\"ls\").start(); } }\n", "megasast/java-processbuilder"),
        ("sample.c", "int main() { FILE *f = popen(\"ls\", \"r\"); }\n", "megasast/c-popen"),
        ("sample.cpp", "int main() { FILE *f = popen(\"ls\", \"r\"); }\n", "megasast/c-popen"),
        ("sample.go", "package sample\nimport \"crypto/tls\"\nvar _ = &tls.Config{InsecureSkipVerify: true}\n", "megasast/go-insecure-skip-verify"),
        ("sample.php", "<?php system($c); ?>\n", "megasast/php-system"),
        ("sample.php", "<?php passthru($c); ?>\n", "megasast/php-passthru"),
        ("sample.php", "<?php proc_open($c, $d, $p); ?>\n", "megasast/php-proc-open"),
        ("sample.php", "<?php $h = popen($c, \"r\"); ?>\n", "megasast/php-popen"),
        ("sample.php", "<?php assert('phpinfo()'); ?>\n", "megasast/php-assert"),
        ("sample.php", "<?php create_function('', $c); ?>\n", "megasast/php-create-function"),
        ("sample.php", "<?php preg_replace('/x/e', $r, $s); ?>\n", "megasast/php-preg-replace-e"),
        ("sample.php", "<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); ?>\n", "megasast/php-curl-no-verify"),
        ("sample.rs", "fn f() { Client::builder().danger_accept_invalid_certs(true); }\n", "megasast/rust-danger-accept-invalid"),
        ("sample.py", "import os\nos.chmod(p, 0o777)\n", "megasast/py-chmod-777"),
        ("sample.py", "import os\nos.mktemp()\n", "megasast/py-os-mktemp"),
        ("sample.py", "import telnetlib\n", "megasast/py-plaintext-protocol"),
        ("sample.py", "from http.server import BaseHTTPRequestHandler\nclass H(BaseHTTPRequestHandler):\n    pass\n", "megasast/py-simple-http-server"),
        ("sample.py", "Environment(loader, autoescape=False)\n", "megasast/py-jinja2-autoescape"),
        ("sample.py", "from django.utils.safestring import mark_safe\nmark_safe(x)\n", "megasast/py-django-mark-safe"),
        ("sample.py", "cursor.execute(f\"select * from t where a={x}\")\n", "megasast/py-sql-fstring"),
        ("sample.py", "app.run(debug=True)\n", "megasast/py-flask-debug"),
        ("sample.py", "import random\nrandom.choice(items)\n", "megasast/insecure-rand"),
        ("sample.js", "el.outerHTML = x;\n", "megasast/js-outerhtml"),
        ("sample.js", "el.insertAdjacentHTML(\"beforeend\", html);\n", "megasast/js-insert-adjacent-html"),
        ("sample.js", "localStorage.setItem(\"authToken\", t);\n", "megasast/js-localstorage-secret"),
        ("sample.js", "crypto.createHash(\"md5\");\n", "megasast/js-crypto-weak-hash"),
        ("sample.js", "setTimeout(\"alert(1)\", 100);\n", "megasast/js-settimeout-string"),
        ("sample.js", "const r = Math.random();\n", "megasast/insecure-rand"),
        ("Sample.java", "class S { void f() { Cipher.getInstance(\"DES\"); } }\n", "megasast/java-cipher-weak"),
        ("Sample.java", "class S { void f() { Signature.getInstance(\"MD5withRSA\"); } }\n", "megasast/java-signature-weak"),
        ("Sample.java", "class S { void f() { stmt.executeQuery(\"select \" + x); } }\n", "megasast/java-sql-concat"),
        ("Sample.java", "class S { void f() { TransformerFactory.newInstance(); } }\n", "megasast/java-xxe"),
        ("Sample.java", "class S { void f() throws Exception { ctx.lookup(name); } }\n", "megasast/java-jndi-lookup"),
        ("Sample.java", "class S { void f() throws Exception { SSLContext.getInstance(\"SSL\"); } }\n", "megasast/java-ssl-protocol"),
        ("Sample.java", "class S { Random r = new Random(); }\n", "megasast/insecure-rand"),
        ("sample.c", "void f(char *b) { scanf(\"%s\", b); }\n", "megasast/c-scanf-s"),
        ("sample.c", "void f(char *d, char *s) { memcpy(d, s, 10); }\n", "megasast/c-memcpy"),
        ("sample.c", "void f(MD5_CTX *c) { MD5_Init(c); }\n", "megasast/c-openssl-weak-hash"),
        ("sample.c", "void f() { DES_set_key(&k, &ks); }\n", "megasast/c-weak-cipher"),
        ("sample.c", "int r = rand();\n", "megasast/insecure-rand"),
        ("sample.c", "char *t = mktemp(tmpl);\n", "megasast/c-mktemp"),
        ("sample.c", "setuid(0);\n", "megasast/c-setuid"),
        ("sample.c", "void f() { chmod(p, 0777); }\n", "megasast/c-chmod-777"),
        ("sample.c", "void f(char *b) { getwd(b); }\n", "megasast/c-getwd"),
        ("sample.c", "char *t = strtok(s, \",\");\n", "megasast/c-strtok"),
        ("sample.c", "int n = atoi(s);\n", "megasast/c-atoi"),
        ("sample.cpp", "void f(char *d, char *s) { memcpy(d, s, 10); }\n", "megasast/c-memcpy"),
        ("sample.go", "package sample\nfunc f() {\n_ = gob.NewDecoder(r).Decode(&v)\n}\n", "megasast/go-gob-decode"),
        ("sample.go", "package sample\nimport \"crypto/des\"\n", "megasast/go-weak-cipher-import"),
        ("sample.go", "package sample\nfunc f() {\n_ = exec.Command(\"sh\", \"-c\", cmd)\n}\n", "megasast/go-exec-shell"),
        ("sample.go", "package sample\nfunc f() {\n_ = db.Query(fmt.Sprintf(\"select %s\", x))\n}\n", "megasast/go-sql-sprintf"),
        ("sample.go", "package sample\nimport \"unsafe\"\n", "megasast/go-unsafe-import"),
        ("sample.go", "package sample\nimport \"math/rand\"\n", "megasast/insecure-rand"),
        ("sample.php", "<?php include $x; ?>\n", "megasast/php-include-variable"),
        ("sample.php", "<?php echo $_REQUEST[\"x\"]; ?>\n", "megasast/php-request-superglobal"),
        ("sample.php", "<?php mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $k, $d, MCRYPT_MODE_CBC); ?>\n", "megasast/php-mcrypt"),
        ("sample.php", "<?php $db->query(\"a\" . $b); ?>\n", "megasast/php-sql-concat"),
        ("sample.php", "<?php mysqli_query($c, \"a\" . $b); ?>\n", "megasast/php-sql-concat"),
        ("sample.php", "<?php extract($_POST); ?>\n", "megasast/php-extract"),
        ("sample.php", "<?php $r = rand(1, 10); ?>\n", "megasast/insecure-rand"),
        ("sample.rs", "fn f(v: Vec<u8>) { String::from_utf8_unchecked(v); }\n", "megasast/rust-from-utf8-unchecked"),
        ("sample.rs", "fn f() { let x: u8 = mem::zeroed(); }\n", "megasast/rust-mem-zeroed"),
        ("sample.rs", "fn f(p: *mut u8) { Vec::from_raw_parts(p, 1, 1); }\n", "megasast/rust-slice-raw-parts"),
        ("sample.rs", "use md5::Digest;\nfn f() {}\n", "megasast/rust-weak-hash-import"),
        ("sample.html", "<a href=\"javascript:alert(1)\">click</a>\n", "megasast/html-js-url"),
        ("sample.html", "<button onclick=\"doThing()\">go</button>\n", "megasast/html-event-handler"),
        ("sample.html", "<a href=\"/docs\" target=\"_blank\">docs</a>\n", "megasast/html-target-blank"),
        ("sample.html", "<script src=\"http://evil.example/app.js\"></script>\n", "megasast/html-insecure-script-src"),
        ("sample.html", "<iframe src=\"http://evil.example/frame\"></iframe>\n", "megasast/html-insecure-iframe-src"),
        ("sample.html", "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">\n", "megasast/html-meta-refresh-js"),
        ("sample.py", "import yaml\nobj = yaml.unsafe_load(stream)\n", "megasast/py-yaml-unsafe-load"),
        ("sample.rs", "fn f(raw: u32) { let x = transmute::<u32, i32>(raw); }\n", "megasast/rust-transmute"),
        ("sample.tsx", "<div>{x}</div>\nel.innerHTML = userInput;\n", "megasast/js-innerhtml"),
        ("sample.yml", "- uses: actions/checkout@v4\n  with:\n    fetch-depth: 0\n", "megasast/yaml-unpinned-action"),
        ("sample.yml", "on:\n  pull_request_target:\n    types: [opened]\njobs:\n  b:\n    runs-on: ubuntu-latest\n", "megasast/yaml-pr-target-trigger"),
        ("sample.yml", "spec:\n  containers:\n    - name: c\n      image: nginx\n      privileged: true\n", "megasast/yaml-k8s-privileged"),
        ("sample.dockerfile", "FROM alpine:3\nRUN curl http://x.example/i.sh | sh\n", "megasast/docker-curl-pipe-sh"),
        ("sample.dockerfile", "FROM alpine:3\nRUN make test\n", "megasast/docker-unpinned-image"),
        ("sample.dockerfile", "FROM busybox:3\nADD https://x.example/f.sh /f.sh\n", "megasast/docker-add-url"),
        ("sample.sh", "eval \"$cmd\"\n", "megasast/sh-eval"),
        ("sample.sh", "curl -fsSL https://x.example/i.sh | sh\n", "megasast/sh-curl-pipe-sh"),
        ("sample.sh", "source \"$1\"\n", "megasast/sh-source-variable"),
        ("sample.rb", "eval(user_input)\n", "megasast/ru-eval"),
        ("sample.rb", "Marshal.load(data)\n", "megasast/ru-marshal-load"),
        ("sample.cs", "Process.Start(cmd, args);\n", "megasast/csharp-process-start"),
        ("sample.cs", "var psi = new ProcessStartInfo { UseShellExecute = true };\n", "megasast/csharp-shell-execute"),
    ],
)
def test_new_rules_match_representative_code(tmp_path, filename, source, expected_rule):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")

    findings = scan_file(path, TreeSitterParser(), allowed_rules={expected_rule})

    assert [finding.rule_id for finding in findings] == [expected_rule]


def test_subprocess_shell_rule_does_not_match_shell_false(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text("import subprocess\nsubprocess.Popen(['echo', 'safe'], shell=False)\n", encoding="utf-8")

    findings = scan_file(path, TreeSitterParser(), allowed_rules={"megasast/py-subprocess-shell"})

    assert findings == []


def test_child_process_exec_sync_rule_does_not_match_other_objects(tmp_path):
    path = tmp_path / "sample.js"
    path.write_text("runner.execSync(command);\n", encoding="utf-8")

    findings = scan_file(path, TreeSitterParser(), allowed_rules={"megasast/js-child-process-exec-sync"})

    assert findings == []


@pytest.mark.parametrize(
    ("filename", "source", "rule_id"),
    [
        ("sample.py", "import subprocess\nsubprocess.run(cmd, shell=False)\n", "megasast/py-subprocess-shell"),
        ("sample.py", "import requests\nrequests.get(url, verify=True)\n", "megasast/py-requests-no-verify"),
        ("sample.js", "cp.spawn(cmd);\n", "megasast/js-spawn-shell"),
        ("sample.go", "package sample\nimport \"crypto/tls\"\nvar _ = &tls.Config{MinVersion: 1}\n", "megasast/go-insecure-skip-verify"),
        ("sample.php", "<?php assert($ok); ?>\n", "megasast/php-assert"),
        ("sample.php", "<?php preg_replace('/x/i', $r, $s); ?>\n", "megasast/php-preg-replace-e"),
        ("sample.php", "<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true); ?>\n", "megasast/php-curl-no-verify"),
        ("sample.php", "<?php curl_setopt($ch, CURLOPT_TIMEOUT, 30); ?>\n", "megasast/php-curl-no-verify"),
        ("sample.py", "import os\n", "megasast/py-plaintext-protocol"),
        ("sample.py", "cursor.execute(\"select * from t where a=%s\", (x,))\n", "megasast/py-sql-fstring"),
        ("sample.py", "app.run(debug=False)\n", "megasast/py-flask-debug"),
        ("sample.py", "import secrets\nsecrets.choice(items)\n", "megasast/insecure-rand"),
        ("sample.js", "localStorage.setItem(\"theme\", t);\n", "megasast/js-localstorage-secret"),
        ("sample.js", "crypto.createHash(\"sha256\");\n", "megasast/js-crypto-weak-hash"),
        ("sample.js", "setTimeout(() => {}, 100);\n", "megasast/js-settimeout-string"),
        ("Sample.java", "class S { void f() { Cipher.getInstance(\"AES\"); } }\n", "megasast/java-cipher-weak"),
        ("Sample.java", "class S { void f() { stmt.executeQuery(\"select * from t\"); } }\n", "megasast/java-sql-concat"),
        ("Sample.java", "class S { SecureRandom r = new SecureRandom(); }\n", "megasast/insecure-rand"),
        ("sample.c", "void f(int *n) { scanf(\"%d\", n); }\n", "megasast/c-scanf-s"),
        ("sample.c", "void f() { chmod(p, 0644); }\n", "megasast/c-chmod-777"),
        ("sample.go", "package sample\nimport \"crypto/aes\"\n", "megasast/go-weak-cipher-import"),
        ("sample.go", "package sample\nfunc f() {\n_ = exec.Command(\"/bin/ls\", \"-l\")\n}\n", "megasast/go-exec-shell"),
        ("sample.go", "package sample\nfunc f() {\n_ = db.Query(\"select *\")\n}\n", "megasast/go-sql-sprintf"),
        ("sample.php", "<?php include \"file.php\"; ?>\n", "megasast/php-include-variable"),
        ("sample.php", "<?php echo $_GET[\"x\"]; ?>\n", "megasast/php-request-superglobal"),
        ("sample.php", "<?php $db->query(\"select *\"); ?>\n", "megasast/php-sql-concat"),
        ("sample.php", "<?php $r = random_int(1, 10); ?>\n", "megasast/insecure-rand"),
        ("sample.rs", "use sha2::Sha256;\nfn f() {}\n", "megasast/rust-weak-hash-import"),
        ("sample.html", "<a href=\"/login\">x</a>\n", "megasast/html-js-url"),
        ("sample.html", "<div class=\"onclick-banner\">x</div>\n", "megasast/html-event-handler"),
        ("sample.html", "<a href=\"/x\" target=\"_self\">y</a>\n", "megasast/html-target-blank"),
        ("sample.html", "<script src=\"https://cdn.example.com/x.js\"></script>\n", "megasast/html-insecure-script-src"),
        ("sample.html", "<iframe src=\"https://ok.example/\" sandbox=\"allow-scripts\"></iframe>\n", "megasast/html-insecure-iframe-src"),
        ("sample.html", "<meta http-equiv=\"refresh\" content=\"30;url=/home\">\n", "megasast/html-meta-refresh-js"),
        ("sample.py", "import yaml\nobj = yaml.safe_load(stream)\n", "megasast/py-yaml-unsafe-load"),
        ("sample.rs", "fn f(raw: u32) { let x = raw as i32; }\n", "megasast/rust-transmute"),
        ("sample.yml", "- uses: actions/checkout@1e31de5f4b6038fe122df8e5d1e3d3e2cf20e7a5\n", "megasast/yaml-unpinned-action"),
        ("sample.yml", "on:\n  pull_request:\n    branches: [main]\n  push:\n    branches: [main]\njobs:\n  b:\n    runs-on: ubuntu-latest\n", "megasast/yaml-pr-target-trigger"),
        ("sample.yml", "spec:\n  containers:\n    - name: c\n      image: nginx\n      privileged: false\n", "megasast/yaml-k8s-privileged"),
        ("sample.dockerfile", "FROM alpine:3\nRUN curl -o /i.sh http://x.example/i.sh\n", "megasast/docker-curl-pipe-sh"),
        ("sample.dockerfile", "FROM alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "megasast/docker-unpinned-image"),
        ("sample.dockerfile", "FROM busybox:3\nADD ./assets/x.sh /x.sh\n", "megasast/docker-add-url"),
        ("sample.sh", "source lib/activate\n", "megasast/sh-source-variable"),
        ("sample.rb", "Marshal.dump(data)\n", "megasast/ru-marshal-load"),
        ("sample.cs", "Process.GetProcesses();\n", "megasast/csharp-process-start"),
        ("sample.cs", "var psi = new ProcessStartInfo { UseShellExecute = false };\n", "megasast/csharp-shell-execute"),
    ],
)
def test_new_rules_do_not_match_safe_code(tmp_path, filename, source, rule_id):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")

    findings = scan_file(path, TreeSitterParser(), allowed_rules={rule_id})

    assert findings == []
