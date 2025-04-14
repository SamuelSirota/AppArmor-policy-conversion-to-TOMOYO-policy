import re

def expand_brace_expressions(pattern: str) -> list:
    """
    Recursively expand alternation expressions like {a,b,c} in the pattern.
    For example: /dir/{a,b}/file  => ["/dir/a/file", "/dir/b/file"]
    """
    m = re.search(r'\{([^}]+)\}', pattern)
    if not m:
        return [pattern]
    pre = pattern[:m.start()]
    alternatives = m.group(1).split(',')
    post = pattern[m.end():]
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
    # If a negative bracket expression is encountered, raise an error.
    if bracket_content.startswith('^'):
        raise NotImplementedError("Negative bracket expressions are not supported for literal expansion.")
    alternatives = expand_bracket_content(bracket_content)
    post = pattern[m.end():]
    results = []
    for alt in alternatives:
        new_pattern = pre + alt + post
        # Recursively process if there is another bracket expression.
        results.extend(expand_bracket_expressions(new_pattern))
    return results

def escape_for_tomoyo(text: str) -> str:
    """
    Escape wildcard characters for TOMOYO.
    (Bracket expressions are assumed to have been expanded and are no longer present.)
    """
    return text.replace("*", r"\*").replace("?", r"\?")

def translate_apparmor_pattern(pattern: str) -> list:
    """
    Translate an AppArmor glob pattern into one or more TOMOYO-compatible patterns.
    
    The translation process:
      - Expands brace expressions ({}).
      - Expands bracket expressions (e.g. [abc] or [a-c]) into literal alternatives.
      - Replaces the recursive wildcard ** with TOMOYO's recursive directory operator "/\{dir\}/".
      - Processes negative glob constructs (e.g. {*^shadow} or {**^shadow,passwd}) by removing the caret
        and inserting TOMOYO’s subtraction operator (here rendered as "\-").
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

# --- Example Usage (for testing) ---

if __name__ == "__main__":
    test_patterns = [
        "/dir/file",                    # specific file
        "/dir/*",                       # simple wildcard
        "/dir/**",                      # recursive wildcard
        "/dir/{a,b}/file",              # alternation expansion
        "/dir/[ab]/file",               # bracket expansion: [ab] becomes 'a' and 'b'
        "/dir/[a-z]/file",              # bracket expansion: [a-c] becomes 'a', 'b', 'c'
        "/etc/{*^shadow}",              # negative glob (non-recursive)
        "/etc/{**^shadow,passwd}"       # alternation with a negative alternative and a plain alternative
    ]
    for pat in test_patterns:
        tomoyo_variants = translate_apparmor_pattern(pat)
        print(f"AppArmor: {pat}")
        print("TOMOYO:")
        for variant in tomoyo_variants:
            print("  " + variant)
        print()
