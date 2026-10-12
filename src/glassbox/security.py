from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_REDACTED = "[REDACTED]"

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
_TOKEN_SHAPES = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abeoprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_AUTH_SCHEME = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}")
# "Basic" is also an ordinary word, so require something that looks encoded.
_BASIC_AUTH = re.compile(
    r"(?i)\b(Basic\s+)(?=[A-Za-z0-9+/]*[0-9+/=])[A-Za-z0-9+/]{16,}={0,2}"
)
# Anchored on the literal "://" so matching stays linear on long inputs.
_URL_USERINFO = re.compile(r"(://[^\s/:@]+:)[^\s/@]+@")
_SECRET_FLAG = re.compile(
    r"(?i)(--?(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|secret|client[_-]?secret))(\s+|=)(?!\[REDACTED\])[^\s,;]+"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|token|password|passwd|secret)\s*[:=]\s*(?!\[REDACTED\])[^\s,;]+"
)

_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|authorization|credentials?)(?:$|[_-])"
)


def redact_text(value: str) -> str:
    redacted = _PRIVATE_KEY_BLOCK.sub(_REDACTED, value)
    for pattern in _TOKEN_SHAPES:
        redacted = pattern.sub(_REDACTED, redacted)
    redacted = _AUTH_SCHEME.sub(rf"\1{_REDACTED}", redacted)
    redacted = _BASIC_AUTH.sub(rf"\1{_REDACTED}", redacted)
    redacted = _URL_USERINFO.sub(rf"\1{_REDACTED}@", redacted)
    redacted = _SECRET_FLAG.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", redacted
    )
    redacted = _SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}={_REDACTED}", redacted)
    return redacted


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            str(key): _REDACTED if _SENSITIVE_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


# --- Deterministic risk assessment -------------------------------------------------

_SHELL_WORDS = frozenset(
    {
        "shell",
        "bash",
        "zsh",
        "sh",
        "exec",
        "execute",
        "command",
        "cmd",
        "terminal",
        "powershell",
        "subprocess",
    }
)
_OUTBOUND_WORDS = frozenset(
    {
        "outbound",
        "send",
        "email",
        "mail",
        "sms",
        "post",
        "publish",
        "upload",
        "webhook",
        "message",
        "notify",
        "tweet",
        "push",
        "share",
    }
)
_MONEY_WORDS = frozenset(
    {"payment", "pay", "purchase", "transfer", "buy", "order", "charge", "refund"}
)
_DESTRUCTIVE_WORDS = frozenset(
    {
        "delete",
        "remove",
        "drop",
        "destroy",
        "purge",
        "truncate",
        "wipe",
        "revoke",
        "terminate",
        "kill",
    }
)
_FILE_WORDS = frozenset({"file", "files", "fs", "notebook", "document", "doc"})
_CHANGE_WORDS = frozenset(
    {
        "write",
        "edit",
        "multiedit",
        "notebookedit",
        "update",
        "create",
        "patch",
        "modify",
        "append",
        "change",
        "set",
        "rename",
        "move",
        "copy",
        "install",
        "config",
        "chmod",
        "chown",
        "deploy",
        "commit",
        "merge",
        "rollback",
        "prune",
    }
)
_READ_WORDS = frozenset(
    {
        "read",
        "get",
        "list",
        "search",
        "view",
        "fetch",
        "query",
        "glob",
        "grep",
        "stat",
        "open",
        "show",
        "describe",
        "inspect",
        "lookup",
    }
)

_SENSITIVE_PATH = re.compile(
    r"""(?ix)
    (?:^|[/\\\s'"=@])\.env(?:\.[\w.-]+)?(?:$|[\s'";|&)<>])
    | (?:^|[/\\~])\.ssh(?:[/\\]|$)
    | \bid_(?:rsa|dsa|ecdsa|ed25519)\b
    | \bauthorized_keys\b
    | \.aws[/\\]credentials
    | \.kube[/\\]config
    | (?:^|[/\\~\s])\.(?:npmrc|pypirc|netrc|git-credentials)\b
    | \.gnupg(?:[/\\]|$)
    | \.(?:pem|p12|pfx|keystore|jks)(?:$|[\s'";|&)<>])
    | \.git[/\\](?:hooks[/\\]|config\b)
    | /etc/(?:passwd|shadow|sudoers|ssh/)
    | (?:^|[/\\\s'"])(?:secrets?|credentials?)(?:\.\w+)?(?:$|[/\\\s'";|&)<>])
    """
)
_SYSTEM_PATH = re.compile(
    r"^(?:/(?:etc|usr|bin|sbin|boot|sys|proc|dev|lib|lib64|var|root|opt)(?:/|$)|[A-Za-z]:\\Windows\\)"
)

_SHELL_HIGH: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), reason)
    for pattern, reason in (
        (r"\b(?:sudo|doas)\b|\bsu\s+-", "runs with elevated privileges"),
        (
            r"\b(?:curl|wget)\b[^;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b",
            "pipes a download into a shell",
        ),
        (
            r"\b(?:curl|wget)\b[^;&]*\|\s*(?:sudo\s+)?(?:python[\d.]*|perl|ruby|node)\b",
            "pipes a download into an interpreter",
        ),
        (
            r"\bbase64\s+(?:-d|--decode)\b[^;&]*\|\s*(?:ba|z)?sh\b",
            "executes decoded content",
        ),
        (r"\beval\b", "evaluates dynamically built code"),
        (
            r"\bdd\b[^;&|]*\bof=|\bmkfs\b|\bfdisk\b|\bparted\b|\bshred\b|\bwipefs\b",
            "writes directly to a disk or destroys data",
        ),
        (r">\s*/dev/(?:sd|nvme|hd|disk|mapper)", "writes directly to a block device"),
        (r"\bchmod\s+(?:-\w+\s+)*[0-7]*777\b", "makes files world-writable"),
        (
            r"\bcho(?:wn|grp)\s+(?:-\w+\s+)*-\w*R",
            "recursively changes file ownership",
        ),
        (
            r"\bgit\s+push\b[^;&|]*(?:--force\b|--force-with-lease\b|\s-f\b|\s\+\S)",
            "force-pushes git history",
        ),
        (
            r"\bgit\s+(?:reset\s+--hard|clean\s+-\w*f|branch\s+-D|checkout\s+--\s|restore\s+(?!--staged))",
            "discards local git work",
        ),
        (
            r"\b(?:drop|truncate)\s+(?:table|database|schema|index)\b",
            "destroys database objects",
        ),
        (r"\bdelete\s+from\s+\w+\s*(?:;|'|\"|$)", "deletes every row of a table"),
        (r"\bkubectl\s+(?:delete|drain)\b", "removes cluster resources"),
        (
            r"\bterraform\s+(?:destroy|apply)\b|\bpulumi\s+(?:destroy|up)\b",
            "changes or destroys infrastructure",
        ),
        (
            r"\bdocker\s+(?:system\s+prune|volume\s+(?:rm|prune)|rmi?\b)",
            "removes containers, images, or volumes",
        ),
        (
            r"\b(?:aws|az|gcloud|doctl)\b[^;&|]*\b(?:delete|terminate|destroy|rb|remove)\b",
            "deletes cloud resources",
        ),
        (
            r"\b(?:shutdown|reboot|halt|poweroff)\b|\bsystemctl\s+(?:stop|disable|mask)\b",
            "stops the machine or a system service",
        ),
        (r"\bkill(?:all)?\s+-(?:9|KILL)\b|\bpkill\b", "force-kills processes"),
        (r":\(\)\s*\{", "fork bomb"),
        (
            r"/dev/tcp/|\b(?:nc|ncat|netcat)\b[^;&|]*\s-\w*e\b",
            "opens a remote shell",
        ),
        (
            r"\bcrontab\b|>>?\s*\S*\.(?:bashrc|zshrc|profile|bash_profile)\b",
            "changes what runs at login or on a schedule",
        ),
        (
            r"\bcurl\b[^;&|]*(?:\s-(?:d|F|T)\b|--data\b|--data-\w+|--form\b|--upload-file\b|-X\s*(?:POST|PUT|PATCH|DELETE))",
            "sends data to a remote host",
        ),
        (
            r"\bwget\b[^;&|]*--post-(?:data|file)|\b(?:scp|sftp|ftp)\b|\brsync\b[^;&|]*\S+:\S",
            "sends data to a remote host",
        ),
        (
            r"\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bgh\s+(?:release\s+create|pr\s+merge|repo\s+delete)\b",
            "publishes outside this machine",
        ),
    )
)
_SHELL_SUBSTITUTION = re.compile(r"`|\$\(|<\(")
_SHELL_REDIRECT = re.compile(r">|<<")
_SHELL_SPLIT = re.compile(r"\|\||&&|[;|\n]")
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Programs that only read, whatever flags they are given. Programs with a
# flag that writes a file or runs another program (sort -o, uniq, rg --pre,
# less, tree -o, date -s, hostname NAME) are deliberately absent.
_READ_ONLY_COMMANDS = frozenset(
    {
        "ls",
        "pwd",
        "cat",
        "head",
        "tail",
        "wc",
        "echo",
        "grep",
        "egrep",
        "fgrep",
        "find",
        "which",
        "whoami",
        "uname",
        "stat",
        "du",
        "df",
        "cut",
        "tr",
        "basename",
        "dirname",
        "realpath",
        "readlink",
        "id",
        "ps",
        "true",
        "test",
        "nl",
        "column",
        "jq",
    }
)
_READ_ONLY_GIT = frozenset(
    {
        "status",
        "log",
        "diff",
        "show",
        "rev-parse",
        "ls-files",
        "blame",
        "describe",
        "shortlog",
        "grep",
    }
)
_FIND_MUTATIONS = re.compile(r"\s-(?:delete|exec|execdir|ok|okdir|fprint\w*|fls)\b")
_GIT_ESCAPES = ("--output", "--ext-diff", "--textconv", "--exec-path", "-c", "-C")
_RM_FLAG = re.compile(
    r"-[A-Za-z]*[rRf][A-Za-z]*|--recursive|--force|--no-preserve-root"
)
_WORD_BREAK = re.compile(r"[\s|()`{}$]+")
_COMMAND_SEPARATOR = re.compile(r"\|\||&&|[;\n]")
# Longer inputs are labeled high without analysis: they cannot be classified
# in bounded time, and an unreadable command deserves attention anyway.
_MAX_COMMAND_CHARS = 20_000
_MAX_STATEMENT_CHARS = 2_000


def _action_words(action: str) -> frozenset[str]:
    return frozenset(word for word in re.split(r"[^a-z0-9]+", action.lower()) if word)


def _segment_is_read_only(segment: str) -> bool:
    words = segment.split()
    if not words or _ENV_ASSIGNMENT.match(words[0]):
        return False
    command = words[0]
    if command == "git":
        return (
            len(words) > 1
            and words[1] in _READ_ONLY_GIT
            and not any(word.startswith(_GIT_ESCAPES) for word in words[2:])
        )
    if command == "find":
        return not _FIND_MUTATIONS.search(segment)
    return command in _READ_ONLY_COMMANDS


def _deletes_recursively(statement: str) -> bool:
    # Plain word scanning: a regular expression over repeated flags is easy to
    # make exponential, and this text is chosen by the agent being recorded.
    words = _WORD_BREAK.split(statement)
    for index, word in enumerate(words):
        if (word == "rm" or word.endswith("/rm")) and any(
            _RM_FLAG.fullmatch(argument) for argument in words[index + 1 :]
        ):
            return True
    return False


def _assess_command(command: str) -> tuple[str, str]:
    if len(command) > _MAX_COMMAND_CHARS:
        return "high", "Command is too long to classify"
    # Patterns run per statement so their cost stays bounded on long input.
    for statement in _COMMAND_SEPARATOR.split(command):
        if len(statement) > _MAX_STATEMENT_CHARS:
            return "high", "Command is too long to classify"
        if _deletes_recursively(statement):
            return "high", "Command recursive or forced delete"
        for pattern, reason in _SHELL_HIGH:
            if pattern.search(statement):
                return "high", f"Command {reason}"
    if _SENSITIVE_PATH.search(command):
        return "high", "Command touches credential or secret material"
    if _SHELL_SUBSTITUTION.search(command):
        return "medium", "Command runs a nested command Glassbox cannot classify"
    without_null = re.sub(r"\d?>\s*/dev/null|2>&1", "", command)
    if _SHELL_REDIRECT.search(without_null):
        return "medium", "Command redirects output into a file"
    segments = [part.strip() for part in _SHELL_SPLIT.split(without_null)]
    segments = [part for part in segments if part]
    if "&" in without_null.replace("&&", ""):
        return "medium", "Command starts a background job"
    if segments and all(_segment_is_read_only(part) for part in segments):
        return "low", "Read-only command"
    return "medium", "Command is not on the read-only list"


def _path_concern(target: str) -> str | None:
    if _SENSITIVE_PATH.search(target):
        return "credential or secret material"
    normalized = target.replace("\\", "/")
    if ".." in normalized.split("/"):
        return "a path that escapes the workspace"
    if _SYSTEM_PATH.match(target):
        return "a system path"
    if normalized.startswith(("/", "~")) or re.match(r"^[A-Za-z]:/", normalized):
        return "a path outside the workspace"
    return None


def assess_risk(
    action: str, target: str = "", metadata: Mapping[str, Any] | None = None
) -> tuple[str, str]:
    """Return a deterministic ``(risk, reason)`` pair for a submitted action.

    The label depends only on the action name, the target, and an optional
    ``metadata["command"]`` string, so the same submission always receives the
    same label. Unrecognized actions are medium rather than low.
    """
    words = _action_words(action)
    if words & _SHELL_WORDS:
        command = target
        if metadata is not None and isinstance(metadata.get("command"), str):
            command = metadata["command"]
        return _assess_command(command)
    if words & _MONEY_WORDS:
        return "high", "Moves money or places an order"
    if words & _OUTBOUND_WORDS:
        return "high", "Sends data outside this machine"
    is_file_action = bool(words & _FILE_WORDS)
    concern = _path_concern(target) if target else None
    if words & _DESTRUCTIVE_WORDS:
        if is_file_action:
            if concern:
                return "high", f"Deletes {concern}"
            return "medium", "Deletes a workspace file"
        return "high", "Destructive action"
    if words & _CHANGE_WORDS:
        if concern and (is_file_action or "config" in words):
            return "high", f"Changes {concern}"
        return "medium", "Changes state"
    if words & _READ_WORDS:
        if concern == "credential or secret material":
            return "medium", "Reads credential or secret material"
        return "low", "Read-only action"
    return "medium", "Unrecognized action; treated as a change"


def classify_risk(
    action: str, target: str = "", metadata: Mapping[str, Any] | None = None
) -> str:
    return assess_risk(action, target, metadata)[0]
