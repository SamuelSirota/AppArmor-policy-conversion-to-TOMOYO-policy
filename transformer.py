from lark import Transformer, v_args

class AppArmorTransformer(Transformer):
    def __init__(self):
        self.policy = AppArmorPolicy()

    # Handle the top-level structure
    def start(self, items):
        # items contains preamble_elements and profiles
        return self.policy

    # Preamble elements
    def include_rule(self, items):
        # items[0] is INCLUDE_DIRECTIVE ("#include")
        # items[1] might be "if exists" (optional)
        # items[2] is the path (QUOTED_STRING or MAGIC_PATH)
        path_idx = 1 if len(items) == 2 else 2
        path = str(items[path_idx]).strip('"')  # Remove quotes if present
        self.policy.includes.append(path)
        return None  # We don't need to return this, it's added to policy

    # Profile handling
    @v_args(inline=True)
    def profile(self, *args):
        profile = AppArmorProfile()
        
        # Handle optional "profile" keyword (args[0] might be "profile")
        start_idx = 1 if str(args[0]) == "profile" else 0
        
        # Set profile name
        profile.name = str(args[start_idx]).strip('"')
        
        # Check for attachment (next arg might be path)
        next_idx = start_idx + 1
        if next_idx < len(args) and isinstance(args[next_idx], str) and args[next_idx] != "{":
            profile.path = str(args[next_idx])
            next_idx += 1
        
        # Check for flags
        if next_idx < len(args) and hasattr(args[next_idx], "children"):  # flags rule
            profile.flags = [str(flag) for flag in args[next_idx].children]
            next_idx += 1
        
        # Rules are in the last argument (block)
        if next_idx < len(args):
            rules_block = args[next_idx]
            if hasattr(rules_block, "children"):
                profile.rules = [rule for rule in rules_block.children if rule is not None]
        
        self.policy.profiles.append(profile)
        return None  # Added to policy, no need to return

    # File rule handling
    @v_args(inline=True)
    def file_rule(self, *args):
        rule = FileRule()
        
        # Handle qualifiers (audit, allow, deny)
        qualifier_idx = 0
        while qualifier_idx < len(args) and str(args[qualifier_idx]) in ["audit", "allow", "deny"]:
            qualifier_idx += 1
        
        # Check for "owner"
        if qualifier_idx < len(args) and str(args[qualifier_idx]) == "owner":
            rule.owner = True
            qualifier_idx += 1
        
        # Find path and permissions
        # Could be "path perms" or "perms path"
        if qualifier_idx + 1 < len(args):
            arg1, arg2 = args[qualifier_idx], args[qualifier_idx + 1]
            if str(arg1).startswith('/'):  # path first
                rule.path = str(arg1)
                rule.permissions = str(arg2)
            else:  # permissions first
                rule.permissions = str(arg1)
                rule.path = str(arg2)
        
        return rule

    # Handle flags list
    def flags(self, items):
        return items  # Return the list of flags for profile to process

    # Handle rules block
    def rules(self, items):
        return [item for item in items if item is not None]  # Filter out None values

    # Ignore comments and other unneeded rules for now
    def line_rule(self, items):
        if items and str(items[0]).startswith('#'):
            return None  # Skip comments
        return items[0] if items else None

    def comma_rule(self, items):
        return items[0] if items else None


class FileRule:
    def __init__(self):
        self.path = ""
        self.permissions = ""
        self.owner = False

    def __str__(self):
        owner_str = "owner " if self.owner else ""
        return f"{owner_str}{self.path} {self.permissions}"

class AppArmorProfile:
    def __init__(self):
        self.name = ""
        self.path = ""
        self.rules = []
        self.flags = []

    def __str__(self):
        lines = []
        header = f"profile {self.name}"
        if self.path:
            header += f" {self.path}"
        if self.flags:
            header += f" flags=({','.join(self.flags)})"
        lines.append(f"{header} {{")
        for rule in self.rules:
            lines.append(f"  {str(rule)},")
        lines.append("}")
        return "\n".join(lines)

class AppArmorPolicy:
    def __init__(self):
        self.profiles = []
        self.includes = []

    def __str__(self):
        lines = []
        for include in self.includes:
            lines.append(f"#include {include}")
        for profile in self.profiles:
            lines.append(str(profile))
        return "\n".join(lines)

if __name__ == "__main__":
    from lark import Lark
    
    # Your grammar (unchanged)
    grammar = """
    %import common.WS
    %ignore WS
    %ignore COMMENT

    COMMENT: /#(?!(include)).*\\r?\\n/
    QUOTED_STRING: /"[^"]*"/
    MAGIC_PATH: /<[^" >][^>]*>/
    VARIABLE: /@\\{[a-zA-Z][a-zA-Z0-9_]*\\}/
    UNQUOTED_FILEGLOB: /\\/[^ \\t\\n\\r\\f\\v,]+/
    UNQUOTED_VALUE: /[^ \\t\\n\\r\\f\\v,]+/
    UNQUOTED_PROFILE_NAME: /[a-zA-Z0-9][^ \\t\\n\\r\\f\\v]*/
    CAPABILITY: /[a-z][a-z_]+/
    PROFILE_FLAG: "complain" | "audit" | "enforce" | "mediate_deleted" | "attach_disconnected" | "chroot_relative"
    SINGLE_ACCESS: "r" | "w" | "a" | "l" | "k" | "m"
    MULTI_ACCESS: "ix" | "ux" | "Ux" | "px" | "Px" | "cx" | "Cx" | "pix" | "Pix" | "cix" | "Cix" | "pux" | "PUx" | "cux" | "CUx" | "x"

    start: (preamble_element | profile)*

    preamble_element: variable_assignment | alias_rule | include_rule | abi_rule

    variable_assignment: VARIABLE ("=" | "+=") value_list
    value_list: (QUOTED_STRING | UNQUOTED_VALUE)+

    alias_rule: "alias" QUOTED_STRING "->" QUOTED_STRING ","

    INCLUDE_DIRECTIVE: "#include"
    include_rule: INCLUDE_DIRECTIVE ["if exists"] (QUOTED_STRING | MAGIC_PATH)

    abi_rule: "abi" (QUOTED_STRING | UNQUOTED_VALUE) [","]

    profile: ["profile"] profile_name [attachment] [flags] "{" rules "}"

    profile_name: QUOTED_STRING | UNQUOTED_FILEGLOB | UNQUOTED_PROFILE_NAME
    attachment: UNQUOTED_FILEGLOB
    flags: ["flags="] "(" flag_list ")"
    flag_list: PROFILE_FLAG ("," PROFILE_FLAG)*

    rules: (line_rule | comma_rule [","] | block_rule)*

    line_rule: (COMMENT | include_rule | abi_rule)

    comma_rule: file_rule | link_rule | capability_rule | network_rule

    capability_rule: qualifiers "capability" capability_list
    capability_list: CAPABILITY+

    network_rule: qualifiers "network" [NETWORK_DOMAIN] [NETWORK_TYPE]

    file_rule: qualifiers ["owner"] file_rule_body
    file_rule_body: ("file" fileglob access | "file" access fileglob | fileglob access | access fileglob) ["->" exec_target]
    fileglob: ["/"] (UNQUOTED_FILEGLOB | VARIABLE) ( ["/"] UNQUOTED_FILEGLOB | VARIABLE)*
    access: (SINGLE_ACCESS | MULTI_ACCESS)+ 
    exec_target: profile_name

    link_rule: qualifiers ["owner"] "link" ["subset"] fileglob "->" fileglob

    block_rule: subprofile
    subprofile: "profile" profile_name [attachment] [flags] "{" rules "}"

    qualifiers: ["audit"] ["allow" | "deny"]
    """

    # Create parser
    parser = Lark(grammar, start='start')
    
    # Example AppArmor policy text
    policy_text = """
    #include <abstractions/base>
    
    profile myprogram /usr/bin/myprogram flags=(complain) {
        /etc/myprogram.conf r,
        /var/log/myprogram.log rw,
    }
    """
    
    # Parse and transform
    tree = parser.parse(policy_text)
    transformer = AppArmorTransformer()
    result = transformer.transform(tree)
    
    # Print the result
    print(result)