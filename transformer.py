"""This module provides a parser and transformer for AppArmor policies.
It includes classes for representing various AppArmor rules, such as file rules,
network rules, and change profile rules.
It also includes functions for converting AppArmor policies to TOMOYO-compatible
domain and exception policies.

This module uses the Lark library for parsing and transforming the AppArmor policy
grammar. The grammar is defined in a separate file (apparmor.lark).
The code was made with the help of ChatGPT o4-mini, Grok 3 mini and GitHub Copilot.
"""

__author__ = "Samuel Martin Sirota"
__year__ = "2025"

from lark import Lark, Transformer
from lark.lexer import Token
import os, re, itertools


class FileRule:
    def __init__(self):
        self.path = ""
        self.permissions = []

    def __str__(self):
        string = ""
        for i in self.permissions:
            string += f"file: {self.path} {i}\n"
        return string.strip()


class LinkRule:
    def __init__(self, source, target):
        self.source = source
        self.target = target

    def __str__(self):
        return f"file link {self.source} -> {self.target}"


class NetworkRule:
    def __init__(self, access, domain, socktype, local=None, peer=None):
        self.access = access
        self.domain = domain
        self.socktype = socktype
        self.local = local or {}
        self.peer = peer or {}

    def __str__(self):
        parts = ["network"]
        if self.access:
            parts.append(",".join(self.access))
        if self.domain:
            parts.append(self.domain)
        if self.socktype:
            parts.append(self.socktype)
        if self.local:
            parts.append("local=" + ",".join(f"{k}={v}" for k, v in self.local.items()))
        if self.peer:
            parts.append("peer=" + ",".join(f"{k}={v}" for k, v in self.peer.items()))
        return " ".join(parts)


class ChangeProfileRule:
    def __init__(self, path, target_profile, mode=None):
        self.path = path
        self.target_profile = target_profile
        self.mode = mode

    def __str__(self):
        m = f"{self.mode} " if self.mode else ""
        return f"change_profile {m}-> {self.path}"


class AppArmorProfile:
    def __init__(self):
        self.identifier = ""
        self.rules = []
        self.flags = []

    def __str__(self):
        flags_str = f" flags=({', '.join(self.flags)})" if self.flags else ""
        rules_str = "\n".join(str(rule) for rule in self.rules)
        return f"profile: {self.identifier}{flags_str} {{\n{rules_str}\n}}"


class AppArmorPolicy:
    def __init__(self):
        self.includes = []
        self.variables = {}
        self.aliases = {}
        self.profiles = []

    def __str__(self):
        lines = []
        for inc in self.includes:
            lines.append(f"#include {inc}")
        for var, value in self.variables.items():
            lines.append(f"{var} = {', '.join(value)}")
        for alias, target in self.aliases.items():
            lines.append(f"alias {alias} -> {target}")
        for profile in self.profiles:
            lines.append(str(profile))
        return "\n".join(lines)


class AppArmorTransformer(Transformer):
    """
    This class transforms the parsed AppArmor policy tree into an internal representation.
    It uses the Lark library to parse the AppArmor policy grammar and convert it into
    a structured format that can be further processed or converted to other formats.
    The transformer methods correspond to the grammar rules defined in the AppArmor
    grammar file (apparmor.lark).
    Each method processes a specific part of the policy and constructs the appropriate
    objects or data structures.
    """
    def __init__(self):
        super().__init__()
        self.policy = AppArmorPolicy()
        self.current_profile = None

    def start(self, items):
        return self.policy

    def include_rule(self, items):
        self.policy.includes.append(str(items[-1]).strip('"<>'))
        return None

    def variable_assignment(self, items):
        var_name = str(items[0])
        raw_rhs = str(items[1]).strip()
        values = raw_rhs.split()
        self.policy.variables.setdefault(var_name, []).extend(values)
        return None

    def path_expr(self, items):
        return "".join(str(i) for i in items)

    def alias_rule(self, items):
        alias = str(items[0]).strip('"')
        target = str(items[1]).strip('"')
        self.policy.aliases[alias] = target
        return f"alias {alias} -> {target}"

    def abi_rule(self, items):
        return

    def line_rule(self, items):
        if items and not (isinstance(items[0], str) and items[0].startswith("#")):
            return items[0]
        return None

    def comma_rule(self, items):
        if items and items[0]:
            return items[0]
        return None

    def block_rule(self, items):
        return items[0]

    def subprofile(self, items):
        profile = AppArmorProfile()
        for item in items[1:]:
            if item is None:
                continue
            elif isinstance(item, tuple):
                key, value = item
                if key == "flags":
                    profile.flags = value
                elif key == "rules":
                    profile.rules.extend(value)
            elif isinstance(item, str):
                if not profile.identifier:
                    profile.identifier = item.strip('"')
            elif isinstance(item, FileRule) or isinstance(item, AppArmorProfile):
                profile.rules.append(item)
        return profile

    def flags(self, items):
        return ("flags", items[-1])

    def flag_list(self, items):
        return [str(flag) for flag in items]

    def rules(self, items):
        clean_rules = [r for r in items if r is not None]
        return ("rules", clean_rules)

    def profile(self, items):
        profileItem = AppArmorProfile()
        for item in items:
            if item is None:
                continue
            elif isinstance(item, tuple):
                key, value = item
                if key == "flags":
                    profileItem.flags = value
                elif key == "rules":
                    profileItem.rules.extend(value)
            elif isinstance(item, str):
                if not profileItem.identifier:
                    profileItem.identifier = item.strip('"')
            elif isinstance(item, FileRule) or isinstance(item, AppArmorProfile):
                profileItem.rules.append(item)
        if self.current_profile is None:
            self.policy.profiles.append(profileItem)
        else:
            for item in profileItem.rules:
                self.policy.profiles[0].rules.append(item)
        self.current_profile = profileItem
        return profileItem

    def qualifiers(self, items):
        return None

    def access(self, items):
        combined_permissions = []
        for item in items:
            if isinstance(item, str):
                combined_permissions.append(item)
        return combined_permissions

    def file_rule_body(self, items):
        tokens = [
            item
            for item in items
            if not (isinstance(item, str) and item in ("file", "->"))
        ]
        if len(tokens) >= 2:
            t0, t1 = tokens[0], tokens[1]
            if isinstance(t0, str) and t0.startswith("/"):
                path = t0
                permissions = t1
            elif isinstance(t1, str) and t1.startswith("/"):
                path = t1
                permissions = t0
            else:
                path = t0
                permissions = t1
            permissions = (
                permissions if isinstance(permissions, list) else [permissions]
            )
            return (path, permissions)
        return ("", [])

    def file_rule(self, items):
        for item in items:
            if isinstance(item, tuple):
                path, permissions = item
                rule = FileRule()
                rule.path = path.strip('"')
                rule.permissions = permissions
                if "w" in rule.permissions and "a" in rule.permissions:
                    raise Exception(f"Permission conflict 'w' and 'a' on {rule.path}")
                return rule
        return FileRule()

    def capability_rule(self, items):
        return  # "capability " + " ".join(str(i) for i in items if isinstance(i, str))

    def network_rule(self, items):
        access = []
        domain = None
        socktype = None
        local = {}
        peer = {}

        for tok in items:
            if isinstance(tok, list) and all(isinstance(a, str) for a in tok):
                access = tok
            elif isinstance(tok, Token) and tok.type == "NETWORK_DOMAIN":
                domain = tok.value
            elif isinstance(tok, Token) and tok.type in ("NETWORK_TYPE", "PROTOCOL"):
                socktype = tok.value
            elif isinstance(tok, tuple) and tok[0] == "local":
                _, key, val = tok
                local[key] = val
            elif isinstance(tok, list) and tok and isinstance(tok[0], tuple):
                for _, key, val in tok:
                    peer[key] = val
        return NetworkRule(access, domain, socktype, local, peer)

    def network_ip_cond(self, items):
        val = items[-1].value if isinstance(items[-1], Token) else items[-1]
        return ("local", "ip", val)

    def network_port_cond(self, items):
        val = items[-1].value
        return ("local", "port", val)

    def network_peer_expr(self, items):
        conds = [c for c in items if isinstance(c, tuple)]
        return [("peer", key, val) for _, key, val in conds]

    def link_rule(self, items):
        source = str(items[1])
        target = str(items[2])
        return LinkRule(source, target)

    def change_profile_rule(self, items):
        mode = None
        path = None
        target = None
        for item in items:
            if item in ("safe", "unsafe"):
                mode = item
            elif isinstance(item, str) and item.startswith("/"):
                path = item.strip('"')
            elif isinstance(item, str) and not item.startswith("/"):
                target = item.strip('"')
        return ChangeProfileRule(path, target, mode)

    def profile_target(self, items):
        return str(items[0]).strip('"')

    def profile_name(self, items):
        return str(items[0]).strip('"')

    def attachment(self, items):
        return str(items[0]).strip('"')

    def fileglob(self, items):
        return "".join(str(i) for i in items)

    def exec_target(self, items):
        return str(items[0]).strip('"')

    def value(self, items):
        return str(items[0]).strip('"')


def expand_variables(path, variables):
    """
    Expand variables in the given path using the provided variable dictionary.
    The variables are expected to be in the format @{var_name}.
    If a variable is not found, it will be replaced with an empty string.
    """
    pattern = re.compile(r"@{([^}]+)}")
    paths = [path]
    while True:
        new_paths = []
        expanded = False
        for p in paths:
            matches = pattern.findall(p)
            if not matches:
                new_paths.append(p)
                continue
            value_lists = []
            for var in matches:
                values = variables.get(f"@{{{var}}}", [])
                if isinstance(values, str):
                    values = values.split()
                value_lists.append(values)
            for combo in itertools.product(*value_lists):
                expanded_p = p
                for var, val in zip(matches, combo):
                    expanded_p = expanded_p.replace(f"@{{{var}}}", val)
                expanded_p = re.sub(r"/{2,}", "/", expanded_p)
                new_paths.append(expanded_p)
                expanded = True
        paths = new_paths
        if not expanded:
            break
    return paths


def apply_aliases(path, aliases):
    """
    Apply alias transformations to the given path using the provided alias dictionary.
    The aliases are expected to be in the format alias_prefix -> target_prefix.
    """
    for alias_prefix, target_prefix in aliases.items():
        if path.startswith(alias_prefix):
            return path.replace(alias_prefix, target_prefix, 1)
    return path


def expand_brace_expressions(pattern: str) -> list:
    """
    Recursively expand a single brace expression in the pattern.
    For example, "/dir/{a,b}/file" expands to ["/dir/a/file", "/dir/b/file"].
    """
    m = re.search(r"\{([^{}]*)\}", pattern)
    if not m:
        return [pattern]
    pre = pattern[: m.start()]

    alternatives = [alt for alt in m.group(1).split(",")]
    post = pattern[m.end() :]
    results = []
    for alt in alternatives:
        for sub in expand_brace_expressions(post):
            results.append(pre + alt + sub)
    return results


def expand_bracket_content(content: str) -> list:
    """
    Expand the content of a bracket expression (assumed to be positive).
    For example, "abc" -> ['a', 'b', 'c'], and "a-c" -> ['a', 'b', 'c'].
    If the content starts with '^', a NotImplementedError is raised.
    """
    if content.startswith("^"):
        raise NotImplementedError(
            "Negative bracket expressions are not supported for literal expansion."
        )
    alternatives = []
    i = 0
    while i < len(content):
        if i + 2 < len(content) and content[i + 1] == "-" and content[i + 2] != "]":
            start = content[i]
            end = content[i + 2]
            for c in range(ord(start), ord(end) + 1):
                alternatives.append(chr(c))
            i += 3
        else:
            alternatives.append(content[i])
            i += 1
    return alternatives


def expand_bracket_expressions(pattern: str) -> list:
    """
    Recursively expand a single bracket expression in the pattern.
    For example, "/dir/[ab]/file" expands to ["/dir/a/file", "/dir/b/file"].
    """
    m = re.search(r"\[([^\]]+)\]", pattern)
    if not m:
        return [pattern]
    pre = pattern[: m.start()]
    bracket_content = m.group(1)
    if bracket_content.startswith("^"):
        raise NotImplementedError(
            "Negative bracket expressions are not supported for literal expansion."
        )
    alternatives = expand_bracket_content(bracket_content)
    post = pattern[m.end() :]
    results = []
    for alt in alternatives:
        new_pattern = pre + alt + post
        results.extend(expand_bracket_expressions(new_pattern))
    return results


def escape_for_tomoyo(text: str) -> str:
    """
    Escape wildcard characters for TOMOYO.
    (Bracket expressions are assumed to have been expanded and are no longer present.)
    """
    return text.replace("*", r"\*").replace("?", r"\?")


def translate_apparmor_pattern(pattern: str) -> list:
    r"""
    Translate an AppArmor glob pattern into one or more TOMOYO-compatible patterns.
    Enhancements:
      - For `**`, produce "/\{dir\}/", "/\{dir\}/\*" and "\*" to include current and subdirectories.
    """
    alternatives = expand_brace_expressions(pattern)
    temp = []
    for alt in alternatives:
        if "[" in alt:
            temp.extend(expand_bracket_expressions(alt))
        else:
            temp.append(alt)
    alternatives = temp

    results = []
    for alt in alternatives:
        sub_patterns = []

        if "^" in alt:
            alt = alt.replace("**^", r"/\{dir\}/\-")
            alt = re.sub(
                r"(\*)(\^)", lambda m: escape_for_tomoyo(m.group(1)) + r"\-", alt
            )
            alt = alt.replace("/^", r"/\-")
            alt = alt.replace("*", r"\*").replace("?", r"\?")
            alt = re.sub(r"(?<!:)/{2,}", "/", alt)
            results.append(alt)
        else:
            parts = alt.split("**")
            if len(parts) == 1:
                alt = alt.replace("*", r"\*").replace("?", r"\?")
                alt = re.sub(r"(?<!:)/{2,}", "/", alt)
                results.append(alt)
            else:
                replacements = [
                    [r"/\{\*\}/\*", r"/\{\*\}/", r"\*"] for _ in range(len(parts) - 1)
                ]
                for combo in itertools.product(*replacements):
                    rebuilt = parts[0]
                    for insert, part in zip(combo, parts[1:]):
                        rebuilt += insert + part
                    rebuilt = rebuilt.replace("?", r"\?")
                    rebuilt = re.sub(r"(?<!\\)\*", r"\\*", rebuilt)
                    rebuilt = re.sub(r"(?<!:)/{2,}", "/", rebuilt)
                    results.append(rebuilt)
    return results


def tomoyo_rewrite_mounts(path: str) -> str:
    """
    Rewrites paths that START with pseudo-filesystem mount points
    into TOMOYO-compatible paths using regex.
    """
    mount_patterns = {
        r"^/proc/": "proc:/",
        r"^/sys/": "sys:/",
        r"^/dev/pts/": "devpts:/",
    }
    print(f"Original path: {path}")
    for pattern, replacement in mount_patterns.items():
        if re.match(pattern, path):
            return re.sub(pattern, replacement, path)
    return path


def convert_to_tomoyo(policy: AppArmorPolicy):
    """
    Convert an AppArmor policy to TOMOYO domain and exception policies.
    This function processes the AppArmor policy and generates TOMOYO-compatible
    domain and exception policies based on the rules defined in the AppArmor policy.
    The conversion includes handling file rules, link rules, change profile rules and network rules.
    The generated TOMOYO policies are returned as strings.
    The function also handles the translation of AppArmor-specific permissions to TOMOYO permissions.
    The TOMOYO domain policy is generated based on the file and network rules, while the exception
    policy is generated based on the change profile rules.
    """
    apparmor_to_tomoyo = {
        "r": ["file read/getattr"],
        "w": [
            "file write",
            "file create",
            "file unlink",
            "file chown",
            "file chgrp",
            "file chmod",
            "file mkdir",
            "file rmdir",
            "file truncate",
            "file rename",
        ],
        "a": ["file append"],
        "x": ["file execute"],
        "ix": ["file execute"],
        "ux": ["file execute"],
        "Ux": ["file execute"],
        "px": ["file execute"],
        "Px": ["file execute"],
        "cx": ["file execute"],
        "Cx": ["file execute"],
        "pix": ["file execute"],
        "Pix": ["file execute"],
        "cix": ["file execute"],
        "Cix": ["file execute"],
        "pux": ["file execute"],
        "PUx": ["file execute"],
        "cux": ["file execute"],
        "CUx": ["file execute"],
        "l": ["file link", "file symlink"],
    }

    apparmor_net_to_tomoyo = {
        "bind": "bind",
        "listen": "listen",
        "connect": "connect",
        "accept": "accept",
        "send": "send",
        "receive": "receive",
    }

    domain_lines = []
    exception_lines = []
    exec_type_mapping = {
        "p": "initialize_domain",
        "P": "initialize_domain",
        "c": "initialize_domain",
        "C": "initialize_domain",
        "u": "reset_domain",
        "U": "reset_domain",
        "i": "keep_domain",
    }
    valid_types = {"stream", "dgram", "seqpacket"}
    valid_accs = {"bind", "listen", "connect", "send"}

    def fmt_addr(d):
        ip = d.get("ip", "NONE")
        port = d.get("port")
        return f"{ip}:{port}" if port else ip

    def process_profile(profile: AppArmorProfile):
        domain_lines.append(
            f"<kernel> {profile.identifier}\nuse_profile 0\nuse_group 0\nfile getattr {profile.identifier}\nfile read {profile.identifier}"
        )
        exception_lines.append(f"initialize_domain {profile.identifier} from any")
        for rule in profile.rules:
            if isinstance(rule, FileRule):
                if "pid" in rule.path:  # i dont like this buuuut it helps [1-4999999]
                    continue
                else:
                    expanded = expand_variables(rule.path, policy.variables)
                    for path in expanded:
                        path = apply_aliases(path, policy.aliases)
                        path = tomoyo_rewrite_mounts(path)
                        variants = (
                            translate_apparmor_pattern(path)
                            if any(c in path for c in "{[?*}")
                            else [path]
                        )
                        for v in variants:
                            for perm in rule.permissions:
                                if perm.endswith("x") and perm[0] in exec_type_mapping:
                                    mode = perm[0]
                                    tom_cmd = exec_type_mapping[mode]
                                    exception_lines.append(
                                        f"{tom_cmd} {v} from {profile.identifier}"
                                    )
                                else:
                                    if perm in apparmor_to_tomoyo:
                                        for tom_perm in apparmor_to_tomoyo[perm]:
                                            domain_lines.append(f"{tom_perm} {v}")
            elif isinstance(rule, LinkRule):
                expanded_source = expand_variables(rule.source, policy.variables)
                expanded_target = expand_variables(rule.target, policy.variables)
                for source in expanded_source:
                    source = apply_aliases(source, policy.aliases)
                    source_variants = (
                        translate_apparmor_pattern(source)
                        if any(c in source for c in "{[?*}")
                        else [source]
                    )
                    for s in source_variants:
                        for target in expanded_target:
                            target = apply_aliases(target, policy.aliases)
                            target_variants = (
                                translate_apparmor_pattern(target)
                                if any(c in target for c in "{[?*}")
                                else [target]
                            )
                            for t in target_variants:
                                domain_lines.append(f"file link {s} {t}")
            elif isinstance(rule, ChangeProfileRule):
                for p in expand_variables(rule.path, policy.variables):
                    p2 = apply_aliases(p, policy.aliases).replace(",", "")
                    exception_lines.append(
                        f"{exec_type_mapping['c']} {p2} from {profile.identifier}"
                    )
            elif isinstance(rule, NetworkRule):
                dom = (rule.domain or "").lower()
                st = (rule.socktype or "").lower()
                accs = set(rule.access or [])
                if dom != "unix" and st not in valid_types and not (accs & valid_accs):
                    continue
                local_addr = fmt_addr(rule.local)
                peers = [rule.peer] if rule.peer else [None]

                for acc in rule.access:
                    tom_op = apparmor_net_to_tomoyo.get(acc, acc)
                    for peer in peers:
                        addr = fmt_addr(peer) if peer else local_addr
                        domain_lines.append(f"network {dom} {st} {tom_op} {addr}")
        domain_lines.append("")

    for prof in policy.profiles:
        process_profile(prof)
    return "\n".join(domain_lines), "\n".join(exception_lines)


def preprocess_policy_file(
    filepath=None,
    seen_files=None,
    base_policy_dir="/etc/apparmor.d",
    relative_include_dir=None,
):
    """
    Preprocess an AppArmor policy file to handle includes and variable expansions.
    This function reads the file, processes any #include directives (including directories),
    and returns the preprocessed content as a string.
    """
    if seen_files is None:
        seen_files = set()
    if filepath is None:
        raise ValueError("You must specify a filepath to preprocess.")
    if relative_include_dir is None:
        raise ValueError("You must specify relative_include_dir for quoted includes.")
    if filepath in seen_files:
        print(f"Skipping already included file: {filepath}")
        return ""
    seen_files.add(filepath)
    result_lines = []

    with open(filepath, "r") as f:
        for line in f:
            line_strip = line.strip()
            if line_strip.startswith("#include") or line_strip.startswith("include"):
                is_conditional = "if exists" in line_strip
                include_path = None

                if "<" in line_strip and ">" in line_strip:
                    raw_path = line_strip.split("<", 1)[1].split(">", 1)[0]
                    include_path = os.path.join(base_policy_dir, raw_path)
                elif '"' in line_strip:
                    raw_path = line_strip.split('"', 1)[1].rsplit('"', 1)[0]
                    include_path = (
                        raw_path
                        if os.path.isabs(raw_path)
                        else os.path.join(relative_include_dir, raw_path)
                    )
                else:
                    raise ValueError(f"Incorrect include directive: {line_strip}")
                if include_path and os.path.isdir(include_path):
                    print(f"Including directory: {include_path}")
                    for entry in sorted(os.listdir(include_path)):
                        entry_path = os.path.join(include_path, entry)
                        if os.path.isfile(entry_path):
                            included_text = preprocess_policy_file(
                                filepath=entry_path,
                                seen_files=seen_files,
                                base_policy_dir=base_policy_dir,
                                relative_include_dir=relative_include_dir,
                            )
                            result_lines.append(included_text)
                    continue
                if include_path and os.path.exists(include_path):
                    print(f"Including file: {include_path}")
                    included_text = preprocess_policy_file(
                        filepath=include_path,
                        seen_files=seen_files,
                        base_policy_dir=base_policy_dir,
                        relative_include_dir=relative_include_dir,
                    )
                    result_lines.append(included_text)
                else:
                    if is_conditional:
                        print(f"Optional include not found: {include_path} (skipping)")
                    else:
                        raise FileNotFoundError(
                            f"Required include file not found: {include_path}"
                        )
            else:
                result_lines.append(line)
    return "".join(result_lines)


if __name__ == "__main__":
    """
    This is the main entry point of the script.
    We use a for loop to iterate over all files in the specified folder.
    For each file, we preprocess it, parse it using the Lark parser,
    and then transform it into an internal representation.
    Finally, we convert the AppArmor policy to TOMOYO domain and exception policies.
    The script handles exceptions and prints the results to the console.
    This script was used in the development of the AppArmor to TOMOYO converter.
    It is not intended to be run as a standalone script.
    """
    with open("apparmor.lark", "r") as f:
        grammar = f.read()
    parser = Lark(grammar, start="start", parser="lalr")
    folder_path = "/home/samos/FEI/ING/year2/diplomovka/tests/fails/"

    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            try:
                print(f"File: {filename}")
                print("-------- Preprocessing --------")
                preprocessed_text = preprocess_policy_file(
                    filepath=file_path,
                    base_policy_dir="/etc/apparmor.d",
                    relative_include_dir=folder_path,
                )
                print(preprocessed_text)
                print("----------- Parsing -----------")
                tree = parser.parse(preprocessed_text)
                print(tree.pretty())
                print("--- Internal Representation ---")
                transformer = AppArmorTransformer()
                result = transformer.transform(tree)
                print(result)
                print("\n---- TOMOYO Domain Policy ----")
                domain_lines, exception_lines = convert_to_tomoyo(result)
                print(domain_lines)
                print("\n--- TOMOYO Exception Policy ---")
                print(exception_lines)
            except Exception as e:
                print("An exception occurred")
                print(e)
            finally:
                print("■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■")
