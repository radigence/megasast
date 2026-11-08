from megasast.rules.base import Rule

# Queries target the tree-sitter-html grammar node vocabulary: document,
# element / script_element / style_element, start_tag, tag_name, attribute,
# attribute_name, quoted_attribute_value, attribute_value, raw_text, text,
# comment. Tag and attribute names are matched case-insensitively because
# HTML is case-insensitive; every filtering predicate sits on a non-root
# capture with @match on the outermost node (see CONTRIBUTING.md).
#
# Attribute values parse three ways, so value checks ship quoted +
# unquoted patterns: quoted_attribute_value > attribute_value,
# bare attribute_value, and valueless (boolean) attributes.

HTML_JS_URL = Rule(
    id="megasast/html-js-url",
    name="HTML javascript: URL",
    description="A javascript: URL in href/src/action/formaction executes script when activated.",
    severity="HIGH",
    languages=["html"],
    queries={
        "html": "(attribute (attribute_name) @n (#match? @n \"(?i)^(href|src|action|formaction|xlink:href)$\") (quoted_attribute_value (attribute_value) @v (#match? @v \"(?i)^[ \\t\\r\\n]*javascript:\"))) @match; "
                "(attribute (attribute_name) @n (#match? @n \"(?i)^(href|src|action|formaction|xlink:href)$\") (attribute_value) @v (#match? @v \"(?i)^[ \\t\\r\\n]*javascript:\")) @match",
    },
    message="javascript: URL — script execution risk.",
    remediation="Use https:// URLs or relative paths. Never build javascript: URLs from untrusted input.",
    tags=["security", "xss"],
    cwe="CWE-79",
    owasp="A03:2021 Injection"
)

HTML_EVENT_HANDLER = Rule(
    id="megasast/html-event-handler",
    name="HTML inline event handler",
    description="Inline on* event handler attributes execute script and are hard to review or sandbox with CSP.",
    severity="MEDIUM",
    languages=["html"],
    queries={
        "html": "(attribute (attribute_name) @n (#match? @n \"(?i)^on[a-z]+$\")) @match",
    },
    message="Inline event handler — potential XSS.",
    remediation="Attach listeners with addEventListener in a separate script file and enforce a script-src Content Security Policy without 'unsafe-inline'.",
    tags=["security", "xss"],
    cwe="CWE-79",
    owasp="A03:2021 Injection"
)

HTML_TARGET_BLANK = Rule(
    id="megasast/html-target-blank",
    name="HTML target=_blank link",
    description="Review-grade heuristic: target=_blank without rel=noopener lets the new page reach window.opener (reverse tabnabbing).",
    severity="LOW",
    languages=["html"],
    queries={
        "html": "(attribute (attribute_name) @n (#match? @n \"(?i)^target$\") (quoted_attribute_value (attribute_value) @v (#match? @v \"(?i)^_blank$\"))) @match; "
                "(attribute (attribute_name) @n (#match? @n \"(?i)^target$\") (attribute_value) @v (#match? @v \"(?i)^_blank$\")) @match",
    },
    message="target=_blank — confirm rel=noopener is set (reverse tabnabbing).",
    remediation="Add rel=\"noopener noreferrer\" to target=_blank links.",
    tags=["security", "tabnabbing"],
    cwe="CWE-1022"
)

HTML_INSECURE_SCRIPT_SRC = Rule(
    id="megasast/html-insecure-script-src",
    name="HTML script loaded over HTTP",
    description="A script src fetched over plaintext HTTP can be tampered with in transit.",
    severity="MEDIUM",
    languages=["html"],
    queries={
        # <script> parses as script_element; element variants cover grammar
        # shifts and error-recovery parses.
        "html": "(script_element (start_tag (tag_name) @t (#match? @t \"(?i)^script$\") (attribute (attribute_name) @n (#match? @n \"(?i)^src$\") (quoted_attribute_value (attribute_value) @v (#match? @v \"(?i)^http://\"))))) @match; "
                "(script_element (start_tag (tag_name) @t (#match? @t \"(?i)^script$\") (attribute (attribute_name) @n (#match? @n \"(?i)^src$\") (attribute_value) @v (#match? @v \"(?i)^http://\")))) @match; "
                "(element (start_tag (tag_name) @t (#match? @t \"(?i)^script$\") (attribute (attribute_name) @n (#match? @n \"(?i)^src$\") (quoted_attribute_value (attribute_value) @v (#match? @v \"(?i)^http://\"))))) @match; "
                "(element (start_tag (tag_name) @t (#match? @t \"(?i)^script$\") (attribute (attribute_name) @n (#match? @n \"(?i)^src$\") (attribute_value) @v (#match? @v \"(?i)^http://\")))) @match",
    },
    message="Script loaded over plaintext HTTP — tampering risk.",
    remediation="Serve scripts over HTTPS from a pinned origin and add subresource integrity (integrity=) hashes.",
    tags=["security", "transport", "mixed-content"],
    cwe="CWE-494",
    owasp="A08:2021 Software and Data Integrity Failures"
)

HTML_INSECURE_IFRAME_SRC = Rule(
    id="megasast/html-insecure-iframe-src",
    name="HTML iframe loaded over HTTP",
    description="An iframe src fetched over plaintext HTTP can be tampered with in transit.",
    severity="MEDIUM",
    languages=["html"],
    queries={
        "html": "(element (start_tag (tag_name) @t (#match? @t \"(?i)^iframe$\") (attribute (attribute_name) @n (#match? @n \"(?i)^src$\") (quoted_attribute_value (attribute_value) @v (#match? @v \"(?i)^http://\"))))) @match; "
                "(element (start_tag (tag_name) @t (#match? @t \"(?i)^iframe$\") (attribute (attribute_name) @n (#match? @n \"(?i)^src$\") (attribute_value) @v (#match? @v \"(?i)^http://\")))) @match",
    },
    message="Iframe loaded over plaintext HTTP — tampering risk.",
    remediation="Serve framed content over HTTPS and restrict it with a sandbox attribute plus frame-ancestors CSP.",
    tags=["security", "transport", "mixed-content"],
    cwe="CWE-829",
    owasp="A08:2021 Software and Data Integrity Failures"
)

HTML_META_REFRESH_JS = Rule(
    id="megasast/html-meta-refresh-js",
    name="HTML meta refresh to javascript: URL",
    description="A meta refresh redirecting to a javascript: URL executes script.",
    severity="MEDIUM",
    languages=["html"],
    queries={
        "html": "(element (start_tag (tag_name) @t (#match? @t \"(?i)^meta$\") (attribute (attribute_name) @n (#match? @n \"(?i)^http-equiv$\") (quoted_attribute_value (attribute_value) @v (#match? @v \"(?i)^refresh$\"))) (attribute (attribute_name) @c (#match? @c \"(?i)^content$\") (quoted_attribute_value (attribute_value) @cv (#match? @cv \"(?i)javascript:\"))))) @match; "
                "(element (start_tag (tag_name) @t (#match? @t \"(?i)^meta$\") (attribute (attribute_name) @n (#match? @n \"(?i)^http-equiv$\") (quoted_attribute_value (attribute_value) @v (#match? @v \"(?i)^refresh$\"))) (attribute (attribute_name) @c (#match? @c \"(?i)^content$\") (attribute_value) @cv (#match? @cv \"(?i)javascript:\")))) @match; "
                "(element (start_tag (tag_name) @t (#match? @t \"(?i)^meta$\") (attribute (attribute_name) @n (#match? @n \"(?i)^http-equiv$\") (attribute_value) @v (#match? @v \"(?i)^refresh$\")) (attribute (attribute_name) @c (#match? @c \"(?i)^content$\") (quoted_attribute_value (attribute_value) @cv (#match? @cv \"(?i)javascript:\"))))) @match; "
                "(element (start_tag (tag_name) @t (#match? @t \"(?i)^meta$\") (attribute (attribute_name) @n (#match? @n \"(?i)^http-equiv$\") (attribute_value) @v (#match? @v \"(?i)^refresh$\")) (attribute (attribute_name) @c (#match? @c \"(?i)^content$\") (attribute_value) @cv (#match? @cv \"(?i)javascript:\")))) @match",
    },
    message="Meta refresh to javascript: URL — script execution risk.",
    remediation="Redirect with an HTTP Location header or a plain https: URL. Never target javascript: URLs.",
    tags=["security", "xss"],
    cwe="CWE-79",
    owasp="A03:2021 Injection"
)

RULES = [
    HTML_JS_URL, HTML_EVENT_HANDLER, HTML_TARGET_BLANK,
    HTML_INSECURE_SCRIPT_SRC, HTML_INSECURE_IFRAME_SRC,
    HTML_META_REFRESH_JS,
]
