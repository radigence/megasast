from megasast.rules.base import Rule

# Dockerfile: instructions are matched by their dedicated node types
# (run_instruction, from_instruction, add_instruction). Whole-instruction
# text predicates are used where the danger is a token pattern rather than
# a single node (curl|sh, unpinned digests).

DOCKER_CURL_PIPE_SH = Rule(
    id="megasast/docker-curl-pipe-sh",
    name="Dockerfile RUN curl|wget piped into a shell",
    description="Piping curl or wget output straight into sh or bash executes a remote payload at build time and provides no integrity checks.",
    severity="HIGH",
    languages=["dockerfile"],
    queries={
        "dockerfile": "(run_instruction (shell_command (shell_fragment) @frag) (#match? @frag \"(curl|wget).*[|][ ]*(sh|bash|zsh|sudo)([ ]|$)\")) @match",
    },
    message="Build step pipes a downloaded script into a shell — remote code execution risk.",
    remediation="Download to a file, verify its checksum or signature, then execute; or install through the package manager.",
    tags=["security", "command-injection", "container"],
    cwe="CWE-494",
    owasp="A08:2021 Software and Data Integrity Failures"
)

DOCKER_UNPINNED_IMAGE = Rule(
    id="megasast/docker-unpinned-image",
    name="Dockerfile FROM without a digest pin",
    description="A base image referenced only by tag (or implicit :latest) is mutable; a rebuilt image can swap in different contents between builds.",
    severity="MEDIUM",
    languages=["dockerfile"],
    queries={
        "dockerfile": "(from_instruction (image_spec) @spec (#not-match? @spec \"@\")) @match",
    },
    message="Base image is not pinned to an immutable digest.",
    remediation="Reference the image by digest (FROM owner/image@sha256:...) built from a policy-managed tag.",
    tags=["security", "supply-chain", "container"],
    cwe="CWE-1357",
    owasp="A08:2021 Software and Data Integrity Failures"
)

DOCKER_ADD_URL = Rule(
    id="megasast/docker-add-url",
    name="Dockerfile ADD with a remote URL",
    description="ADD with a URL downloads the file at build time without authentication or integrity verification; it also adds a cache bloating layer.",
    severity="MEDIUM",
    languages=["dockerfile"],
    queries={
        "dockerfile": "(add_instruction (path) @src (#match? @src \"^[a-zA-Z][a-zA-Z0-9+.-]*://\")) @match",
    },
    message="ADD fetches a remote URL at build time.",
    remediation="Use COPY for local files, or download with curl/wget plus a checksum verification.",
    tags=["security", "container"],
    cwe="CWE-494",
    owasp="A08:2021 Software and Data Integrity Failures"
)

RULES = [DOCKER_CURL_PIPE_SH, DOCKER_UNPINNED_IMAGE, DOCKER_ADD_URL]
