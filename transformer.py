from lark import Lark, Transformer
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
        self.includes = []    # List of include paths
        self.variables = {}   # Dictionary for variable assignments
        self.aliases = {}     # Dictionary for alias rules
        self.profiles = []    # List of AppArmorProfiles
    
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

    # RULES
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
        tokens = [item for item in items if not (isinstance(item, str) and item in ("file", "->"))]
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
            permissions = permissions if isinstance(permissions, list) else [permissions]
            return (path, permissions)
        return ("", [])

    def file_rule(self, items):
        for item in items:
            if isinstance(item, tuple):
                path, permissions = item
                rule = FileRule()
                rule.path = path.strip('"')
                rule.permissions = permissions
                if 'w' in rule.permissions and 'a' in rule.permissions:
                    raise Exception(f"Permission conflict 'w' and 'a' on {rule.path}")
                return rule
        return FileRule()

    def capability_rule(self, items):
        return "capability " + " ".join(str(i) for i in items if isinstance(i, str))

    def network_rule(self, items):
        return "network " + " ".join(str(i) for i in items if isinstance(i, str))
    
    def change_profile_rule(self, items):
        return "change_profile -> " + " ".join(str(i) for i in items if isinstance(i, str))

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
    pattern = re.compile(r'@{([^}]+)}')

    # Find all variables used in the path
    matches = pattern.findall(path)
    if not matches:
        return [path]  # No variables to expand

    # For each match, get corresponding values
    value_lists = []
    for var in matches:
        values = variables.get(f'@{{{var}}}', [])
        value_lists.append(values)

    # Generate all combinations (cartesian product)
    combinations = list(itertools.product(*value_lists))

    # Build the expanded paths
    expanded_paths = []
    for combo in combinations:
        expanded = path
        for var, val in zip(matches, combo):
            expanded = expanded.replace(f'@{{{var}}}', val)
        expanded_paths.append(expanded)

    return expanded_paths

def apply_aliases(path, aliases):
    for alias_prefix, target_prefix in aliases.items():
        if path.startswith(alias_prefix):
            return path.replace(alias_prefix, target_prefix, 1)
    return path

def expand_brace_expressions(pattern: str) -> list:
    m = re.search(r'\{([^{}]*)\}', pattern)
    if not m:
        return [pattern]
    pre = pattern[:m.start()]
    # explicitly keep empty alternatives
    alternatives = [alt for alt in m.group(1).split(',')]
    post = pattern[m.end():]
    results = []
    for alt in alternatives:
        # Even if alt is empty, add it back explicitly.
        for sub in expand_brace_expressions(post):
            results.append(pre + alt + sub)
    return results


def expand_bracket_content(content: str) -> list:
    """
    Expand the content of a bracket expression (assumed to be positive).
    For example, "abc" -> ['a', 'b', 'c'], and "a-c" -> ['a', 'b', 'c'].
    If the content starts with '^', a NotImplementedError is raised.
    """
    if content.startswith('^'):
        raise NotImplementedError("Negative bracket expressions are not supported for literal expansion.")
    alternatives = []
    i = 0
    while i < len(content):
        # Handle character ranges such as a-c
        if i + 2 < len(content) and content[i+1] == '-' and content[i+2] != ']':
            start = content[i]
            end = content[i+2]
            for c in range(ord(start), ord(end)+1):
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
    m = re.search(r'\[([^\]]+)\]', pattern)
    if not m:
        return [pattern]
    pre = pattern[:m.start()]
    bracket_content = m.group(1)
    if bracket_content.startswith('^'):
        raise NotImplementedError("Negative bracket expressions are not supported for literal expansion.")
    alternatives = expand_bracket_content(bracket_content)
    post = pattern[m.end():]
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
    # First, expand curly-brace alternations.
    alternatives = expand_brace_expressions(pattern)
    # Then, expand any bracket expressions.
    temp = []
    for alt in alternatives:
        if '[' in alt:
            temp.extend(expand_bracket_expressions(alt))
        else:
            temp.append(alt)
    alternatives = temp

    results = []
    for alt in alternatives:
        # --- Handle negative glob constructs that include a caret ---
        if "^" in alt:
            # Replace recursive negative: if "**^" is found, replace with recursive operator and negative marker.
            alt = alt.replace("**^", r"/\{dir\}/\-")
            # Replace an asterisk immediately followed by a caret with escaped asterisk plus "\-"
            alt = re.sub(r'(\*)(\^)', lambda m: escape_for_tomoyo(m.group(1)) + r"\-", alt)
            # Also replace "/^" with "/\-"
            alt = alt.replace("/^", r"/\-")
        else:
            # Replace recursive wildcard: ** → /\{dir\}/
            alt = alt.replace("**", r"/\{dir\}/")
        # Remove duplicate slashes (except at the beginning).
        alt = re.sub(r'(?<!:)/{2,}', '/', alt)
        # Escape any remaining wildcards: * and ?.
        alt = alt.replace("*", r"\*").replace("?", r"\?")
        results.append(alt)
    return results

def convert_to_tomoyo(policy: AppArmorPolicy):
    apparmor_to_tomoyo = {
        "r": ["file read", "file getattr"],
        "w": ["file write", "file create", "file unlink", "file chown", "file chgrp", "file chmod", "file mkdir", "file rmdir", "file truncate", "file rename"],
        "a": ["file append"],
        "x": ["file execute"],
        "ux": ["file execute"],
        "Ux": ["file execute"],
        "px": ["file execute"],
        "Px": ["file execute"],
        "cx": ["file execute"],
        "Cx": ["file execute"],
        "ix": ["file execute"],
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

    tomoyo_lines = []

    def process_profile(profile: AppArmorProfile):
        profile_identifier = profile.identifier or "<unnamed>"
        tomoyo_lines.append(f"TOMOYO profile: {profile_identifier}")
        
        for rule in profile.rules:
            if isinstance(rule, FileRule):
                expanded_paths = expand_variables(rule.path, policy.variables)
                for expanded_path in expanded_paths:
                    # Apply alias transformation.
                    expanded_path = apply_aliases(expanded_path, policy.aliases)

                    # --- NEW: Translate AppArmor pattern to TOMOYO-compatible patterns ---
                    if any(c in expanded_path for c in "{[?*"):
                        # Use the pattern translator to generate variants.
                        tomoyo_variants = translate_apparmor_pattern(expanded_path)
                    else:
                        tomoyo_variants = [expanded_path]

                    # Optional: Retain existing glob expansion for file resolution (if required)
                    # Uncomment the following block if you want to resolve concrete file matches.
                    # if any(c in expanded_path for c in "*?["):
                    #     matched_paths = resolve_globbed_paths(expanded_path, root="/")
                    # else:
                    #     matched_paths = [expanded_path]

                    # Process each translated variant with its permissions.
                    for variant in tomoyo_variants:
                        for perm in rule.permissions:
                            if perm in apparmor_to_tomoyo:
                                for tomoyo_perm in apparmor_to_tomoyo[perm]:
                                    tomoyo_lines.append(f"{tomoyo_perm} {variant}")
                            else:
                                tomoyo_lines.append(f"unknown permission: {perm} on {variant}")
            elif isinstance(rule, AppArmorProfile):
                process_profile(rule)
            elif isinstance(rule, str):
                tomoyo_lines.append(f"skip, nonfile rule: {rule}")
        tomoyo_lines.append("")

    for profile in policy.profiles:
        process_profile(profile)

    return "\n".join(tomoyo_lines)



def preprocess_policy_file(filepath=None, seen_files=None, base_policy_dir="/etc/apparmor.d", relative_include_dir=None):
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
                    start = line_strip.find("<") + 1
                    end = line_strip.find(">")
                    raw_path = line_strip[start:end]
                    include_path = os.path.join(base_policy_dir, raw_path)
                elif '"' in line_strip:
                    start = line_strip.find('"') + 1
                    end = line_strip.rfind('"')
                    raw_path = line_strip[start:end]
                    if raw_path.startswith("/"):
                        include_path = raw_path
                    else:
                        include_path = os.path.join(relative_include_dir, raw_path)
                else:
                    raise ValueError(f"Incorrect include directive: {line_strip}")

                if include_path:
                    if os.path.exists(include_path):
                        print(f"Including file: {include_path}")
                        included_text = preprocess_policy_file(include_path, seen_files, base_policy_dir, relative_include_dir)
                        result_lines.append(included_text)
                    else:
                        if is_conditional:
                            print(f"Optional include not found: {include_path} (skipping)")
                        else:
                            raise FileNotFoundError(f"Required include file not found: {include_path}")
            else:
                result_lines.append(line)

    return "".join(result_lines)


if __name__ == "__main__":
    with open("apparmor.lark", "r") as f:
        grammar = f.read()

    parser = Lark(grammar, start="start", parser="lalr")
    for token in parser.lex('/bin/mount ux,'):
        print(token)
    folder_path = "/home/samos/FEI/ING/year2/diplomovka/tests/passes/"
    
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            try:
                print(f"File: {filename}")
                print("-------- Preprocessing --------")
                preprocessed_text = preprocess_policy_file(filepath=file_path,base_policy_dir=folder_path, relative_include_dir=folder_path)
                print("----------- Parsing -----------")
                tree = parser.parse(preprocessed_text)
                print(tree.pretty())
                print("--- Internal Representation ---")
                transformer = AppArmorTransformer()
                result = transformer.transform(tree)
                print(result)
                print("\n-------- TOMOYO Policy --------")
                tomoyo_output = convert_to_tomoyo(result)
                print(tomoyo_output)
            except Exception as e:
                print("An exception occurred")
                print(e)
            finally:
                print("■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■")
                
