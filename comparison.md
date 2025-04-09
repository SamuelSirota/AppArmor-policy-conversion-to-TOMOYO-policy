| **Feature / Rule Type**             | **Status in Lark Grammar**     | **Notes** |
|------------------------------------|-------------------------------|----------|
| `pivot_root` rule                  | ❌ Missing                     | Not present in the Lark grammar. |
| `signal` rule                      | ❌ Missing                     | No parsing rules for `signal`. |
| `ptrace` rule                      | ❌ Missing                     | Absent from grammar. |
| `mqueue` rule                      | ❌ Missing                     | Not included. |
| `dbus` rule                        | ❌ Missing                     | No dbus rules found. |
| `change_profile` rule             | ❌ Missing                     | Not defined in grammar. |
| `rlimit` rule                      | ❌ Missing                     | Not implemented in grammar. |
| `link` rule                        | ❌ Missing                     | `link` with `subset` and `->` missing. |
| `hat` / `^` subprofile             | ❌ Missing                     | `hat` or `^` syntax for child profiles not handled. |
| `abi` preamble                     | ❌ Missing                     | The grammar doesn't account for the ABI line. |
| `owner` qualifier                  | ⚠️ Partial                     | Not clearly handled—if `owner` exists, it’s not separated explicitly. |
| `exec_mode` in `change_profile`   | ❌ Missing                     | `safe` and `unsafe` options not modeled. |
| `unix` rule                        | ⚠️ Partial                     | Present but lacks full conditional handling (`type=`, `peer=`, etc.). |
| `mount` rule                       | ⚠️ Partial                     | Basic support exists, but lacks `options=`, `in`, and nested conditions. |
| `comment`                         | ✅ Present                     | Handled. |
| `include` / `#include`            | ✅ Present                     | Supported in grammar. |
| `capability` rule                  | ✅ Present                     | Included. |
| `network` rule                     | ✅ Present                     | Present. |
| `file` rule                        | ✅ Present                     | Included, with `rwx` access modes. |
| `variable` definitions             | ✅ Present                     | Grammar parses `@{VAR}` syntax. |
| `alias` rule                       | ✅ Present                     | Found in Lark grammar. |
| `profile` head & structure         | ✅ Present                     | Profiles and nested profiles parsed. |
| `audit`, `allow`, `deny`          | ✅ Present                     | Included via qualifiers. |
