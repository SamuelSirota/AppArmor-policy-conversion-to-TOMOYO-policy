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
            parts.append("local="+",".join(f"{k}={v}" for k,v in self.local.items()))
        if self.peer:
            parts.append("peer="+",".join(f"{k}={v}" for k,v in self.peer.items()))
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
        self.includes = []  # List of include paths
        self.variables = {}  # Dictionary for variable assignments
        self.aliases = {}  # Dictionary for alias rules
        self.profiles = []  # List of AppArmorProfiles

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
        values = [str(v).strip('"') for v in items[1:]]
        if var_name not in self.policy.variables:
            self.policy.variables[var_name] = []
        self.policy.variables[var_name].extend(values)
        return None

    def alias_rule(self, items):
        alias = str(items[0]).strip('"')
        target = str(items[1]).strip('"')
        self.policy.aliases[alias] = target
        return f"alias {alias} -> {target}"

    def abi_rule(self, items):
        return "abi " + str(items[0]).strip('"')

    def line_rule(self, items):
        if items and not (isinstance(items[0], str) and items[0].startswith("#")):
            return items[0]
        return None

    def comma_rule(self, items):
        return items[0]

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
        profile = AppArmorProfile()
        for item in items:
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
        if self.current_profile is None:
            self.policy.profiles.append(profile)
        self.current_profile = profile
        return profile

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
        return "capability " + " ".join(str(i) for i in items if isinstance(i, str))

    def network_rule(self, items):
        access = []
        domain = None
        socktype = None
        local = {}
        peer  = {}

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
    matches = pattern.findall(path)
    if not matches:
        return [path]
    value_lists = []
    for var in matches:
        values = variables.get(f"@{{{var}}}", [])
        value_lists.append(values)
    expanded_paths = []
    for combo in itertools.product(*value_lists):
        expanded = path
        for var, val in zip(matches, combo):
            expanded = expanded.replace(f"@{{{var}}}", val)
        expanded = re.sub(r"/{2,}", "/", expanded)
        expanded_paths.append(expanded)
    return expanded_paths


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

    The translation process:
      - Expands brace expressions ({}).
      - Expands bracket expressions (e.g. [abc] or [a-c]) into literal alternatives.
      - Replaces the recursive wildcard ** with TOMOYO's recursive directory operator "/\{dir\}/".
      - Processes negative glob constructs (e.g. {*^shadow} or {**^shadow,passwd}) by removing the caret
        and inserting TOMOYO subtraction operator (here rendered as "\-").
      - Escapes standard wildcards (* and ?), so they become "\*" and "\?".
      - Removes duplicate slashes (except at the beginning).
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
        if "^" in alt:
            alt = alt.replace("**^", r"/\{dir\}/\-")
            alt = re.sub(
                r"(\*)(\^)", lambda m: escape_for_tomoyo(m.group(1)) + r"\-", alt
            )
            alt = alt.replace("/^", r"/\-")
        else:
            alt = alt.replace("**", r"/\{dir\}/")
        alt = re.sub(r"(?<!:)/{2,}", "/", alt)
        alt = alt.replace("*", r"\*").replace("?", r"\?")
        results.append(alt)
    return results


def convert_to_tomoyo(policy: AppArmorPolicy):
    """
    Convert AppArmor policy to TOMOYO format, but skip only when:
      1) domain != "unix"
      2) AND socktype not in {stream,dgram,seqpacket}
      3) AND access ∩ {bind,listen,connect,send} is empty
    Everything else (including unix-domain binds) is emitted.
    """
    apparmor_to_tomoyo = {
        "r": ["file read", "file getattr"],
        "w": [
            "file write", "file create", "file unlink", "file chown",
            "file chgrp", "file chmod", "file mkdir", "file rmdir",
            "file truncate", "file rename",
        ],
        "a": ["file append"],
        "x": ["file execute"],  "ix": ["file execute"],  "ux": ["file execute"],
        "Ux": ["file execute"], "px": ["file execute"],  "Px": ["file execute"],
        "cx": ["file execute"], "Cx": ["file execute"],  "pix": ["file execute"],
        "Pix": ["file execute"],"cix": ["file execute"], "Cix": ["file execute"],
        "pux": ["file execute"],"PUx": ["file execute"], "cux": ["file execute"],
        "CUx": ["file execute"],
        "l": ["file link", "file symlink"],
    }

    apparmor_net_to_tomoyo = {
        "bind":    "bind",
        "listen":  "listen",
        "connect": "connect",
        "accept":  "accept",
        "send":    "send",
        "receive": "receive",
    }

    domain_lines = []
    exception_lines = []
    exec_type_mapping = {
        'p': 'initialize_domain',   # exec to profile, no scrub
        'P': 'initialize_domain',   # exec to profile, with scrub
        'c': 'initialize_domain',   # exec to child profile, no scrub
        'C': 'initialize_domain',   # exec to child profile, with scrub
        'u': 'reset_domain',        # exec unconfined, no scrub
        'U': 'reset_domain',        # exec unconfined, with scrub
        'i': 'keep_domain',         # inherit current confinement
    }
    valid_types = {"stream", "dgram", "seqpacket"}
    valid_accs  = {"bind", "listen", "connect", "send"}

    def fmt_addr(d):
        ip   = d.get("ip", "NONE")
        port = d.get("port")
        return f"{ip}:{port}" if port else ip

    def process_profile(profile: AppArmorProfile):
        domain_lines.append(f"TOMOYO profile: {profile.identifier or '<unnamed>'}")
        for rule in profile.rules:
            if isinstance(rule, FileRule):
                expanded = expand_variables(rule.path, policy.variables)
                for path in expanded:
                    path = apply_aliases(path, policy.aliases)
                    variants = (
                        translate_apparmor_pattern(path)
                        if any(c in path for c in "{[?*}") else [path]
                    )
                    for v in variants:
                        for perm in rule.permissions:
                            if perm.endswith('x') and perm[0] in exec_type_mapping:
                                mode = perm[0]
                                tom_cmd = exec_type_mapping[mode]
                                exception_lines.append(f"{tom_cmd} {v} from {profile.identifier}")
                            else:
                                for tom_perm in apparmor_to_tomoyo.get(perm, [f"unknown {perm}"]):
                                    domain_lines.append(f"{tom_perm} {v}")

            elif isinstance(rule, LinkRule):
                expanded_source = expand_variables(rule.source, policy.variables)
                expanded_target = expand_variables(rule.target, policy.variables)
                for source in expanded_source:
                    source = apply_aliases(source, policy.aliases)
                    source_variants = (
                        translate_apparmor_pattern(source)
                        if any(c in source for c in "{[?*}") else [source]
                    )
                    for s in source_variants:
                        for target in expanded_target:
                            target = apply_aliases(target, policy.aliases)
                            target_variants = (
                                translate_apparmor_pattern(target)
                                if any(c in target for c in "{[?*}") else [target]
                            )
                            for t in target_variants:
                                domain_lines.append(f"file link {s} {t}")
            
            elif isinstance(rule, ChangeProfileRule):
                for p in expand_variables(rule.path, policy.variables):
                    p2 = apply_aliases(p, policy.aliases).replace(",", "")
                    domain_lines.append(f"domain change {profile.identifier} -> {p2}")

            elif isinstance(rule, NetworkRule):
                dom  = (rule.domain or "").lower()
                st   = (rule.socktype or "").lower()
                accs = set(rule.access or [])
                if dom != "unix" and st not in valid_types and not (accs & valid_accs):
                    continue
                local_addr = fmt_addr(rule.local)
                peers      = [rule.peer] if rule.peer else [None]

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

                # Determine the include target
                if "<" in line_strip and ">" in line_strip:
                    raw_path = line_strip.split("<", 1)[1].split(">", 1)[0]
                    include_path = os.path.join(base_policy_dir, raw_path)
                elif '"' in line_strip:
                    raw_path = line_strip.split('"', 1)[1].rsplit('"', 1)[0]
                    include_path = raw_path if os.path.isabs(raw_path) else os.path.join(relative_include_dir, raw_path)
                else:
                    raise ValueError(f"Incorrect include directive: {line_strip}")

                # Handle directory includes
                if include_path and os.path.isdir(include_path):
                    print(f"Including directory: {include_path}")
                    for entry in sorted(os.listdir(include_path)):
                        entry_path = os.path.join(include_path, entry)
                        if os.path.isfile(entry_path):
                            # Recursively preprocess each file in the directory
                            included_text = preprocess_policy_file(
                                filepath=entry_path,
                                seen_files=seen_files,
                                base_policy_dir=base_policy_dir,
                                relative_include_dir=relative_include_dir,
                            )
                            result_lines.append(included_text)
                    continue  # Move to next line after processing directory

                # Handle file includes
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
    with open("apparmor.lark", "r") as f:
        grammar = f.read()
    parser = Lark(grammar, start="start", parser="lalr")
    folder_path = "/home/samos/FEI/ING/year2/diplomovka/tests/passes/"

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
                domain_lines, exception_lines  = convert_to_tomoyo(result)
                print(domain_lines)
                print("\n--- TOMOYO Exception Policy ---")
                print(exception_lines)
            except Exception as e:
                print("An exception occurred")
                print(e)
            finally:
                print("■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■")
