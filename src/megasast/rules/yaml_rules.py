from megasast.rules.base import Rule

# YAML: GitHub Actions workflow and Kubernetes manifest hygiene. Keys are
# matched as flow_node/plain_scalar/string_scalar (block-mapping keys); the
# boolean scalar type maps unquoted true/false values.

YAML_UNPINNED_ACTION = Rule(
    id="megasast/yaml-unpinned-action",
    name="GitHub Action action pinned to a mutable ref",
    description="A `uses:` reference is not pinned to a full 40-character commit SHA. Tags and branches are mutable, so a compromised action repository can inject code into workflows.",
    severity="MEDIUM",
    languages=["yaml"],
    queries={
        "yaml": "(block_mapping_pair key: (flow_node (plain_scalar (string_scalar) @key)) value: (flow_node (plain_scalar (string_scalar) @val)) (#eq? @key \"uses\") (#not-match? @val \"@[a-f0-9]{40}$\")) @match",
    },
    message="Action reference is not pinned to a commit SHA — supply-chain risk.",
    remediation="Pin third-party actions to a full commit SHA (owner/repo@<40-char-sha>) after reviewing the commit.",
    tags=["security", "supply-chain", "ci-config"],
    cwe="CWE-1357",
    owasp="A08:2021 Software and Data Integrity Failures"
)

YAML_PR_TARGET_TRIGGER = Rule(
    id="megasast/yaml-pr-target-trigger",
    name="GitHub workflow trigger pull_request_target",
    description="pull_request_target workflows run in the context of the base repository with access to secrets, and checkout of untrusted PR code followed by any script execution leads to code execution.",
    severity="MEDIUM",
    languages=["yaml"],
    queries={
        # on:
        #   pull_request_target:
        "yaml": (
            "(block_mapping_pair key: (flow_node (plain_scalar (string_scalar) @on)) "
            "value: (block_node (block_mapping (block_mapping_pair key: (flow_node (plain_scalar (string_scalar) @evt))))) "
            "(#eq? @on \"on\") (#eq? @evt \"pull_request_target\")) @match; "
            "(block_mapping_pair key: (flow_node (plain_scalar (string_scalar) @on)) "
            "value: (flow_node (plain_scalar (string_scalar) @evt)) "
            "(#eq? @on \"on\") (#eq? @evt \"pull_request_target\")) @match"
        ),
    },
    message="Workflow triggers on pull_request_target — secrets are exposed to PR-derived workflow logic.",
    remediation="Use pull_request instead, or audit the workflow so no checkout of the PR head and no script execution happens before an approval gate.",
    tags=["security", "ci-config", "github-actions"],
    cwe="CWE-20",
    owasp="A05:2021 Security Misconfiguration"
)

YAML_K8S_PRIVILEGED = Rule(
    id="megasast/yaml-k8s-privileged",
    name="Privileged Kubernetes container",
    description="privileged: true grants the container near-full root access to the host machine.",
    severity="HIGH",
    languages=["yaml"],
    queries={
        "yaml": "(block_mapping_pair key: (flow_node (plain_scalar (string_scalar) @key)) value: (flow_node (plain_scalar (boolean_scalar) @val)) (#eq? @key \"privileged\") (#eq? @val \"true\")) @match",
    },
    message="Container runs with privileged: true — host escape risk.",
    remediation="Run with the least privilege required; if a privileged capability is needed, add that single capability instead.",
    tags=["security", "container", "kubernetes"],
    cwe="CWE-250",
    owasp="A05:2021 Security Misconfiguration"
)

RULES = [YAML_UNPINNED_ACTION, YAML_PR_TARGET_TRIGGER, YAML_K8S_PRIVILEGED]
