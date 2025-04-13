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
        self.name = ""
        self.path = ""
        self.rules = []
        self.flags = []

    def __str__(self):
        flags_str = f" flags=({', '.join(self.flags)})" if self.flags else ""
        rules_str = "\n".join(str(rule) for rule in self.rules)
        return f"profile: {self.name} {self.path}{flags_str} {{\n{rules_str}\n}}"

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
                if not profile.name:
                    profile.name = item.strip('"')
                elif not profile.path:
                    profile.path = item.strip('"')
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
                if not profile.name:
                    profile.name = item.strip('"')
                elif not profile.path:
                    profile.path = item.strip('"')
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
        profile_name = profile.name or "<unnamed>"
        tomoyo_lines.append(f"TOMOYO profile: {profile_name} ({profile.path})")
        
        for rule in profile.rules:
            if isinstance(rule, FileRule):
                expanded_paths = expand_variables(rule.path, policy.variables)
                for expanded_path in expanded_paths:
                    expanded_path = apply_aliases(expanded_path, policy.aliases)
                    for perm in rule.permissions:
                        if perm in apparmor_to_tomoyo:
                            for tomoyo_perm in apparmor_to_tomoyo[perm]:
                                tomoyo_lines.append(f"{tomoyo_perm} {expanded_path}")
                        else:
                            tomoyo_lines.append(f"unknown permission: {perm} on {expanded_path}")
            elif isinstance(rule, AppArmorProfile):
                # RECURSION
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
                
