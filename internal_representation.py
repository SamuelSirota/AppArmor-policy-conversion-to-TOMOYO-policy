class FileRule:
    def __init__(self):
        self.path = ""
        self.permissions = []  # "r", "w", "rw", "ix", ...

    def __str__(self):
        return f"{self.path} {self.permissions}"

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
    policy = AppArmorPolicy()
    
    policy.includes.append("<abstractions/base>")
    
    profile = AppArmorProfile()
    profile.name = "myprogram"
    profile.path = "/usr/bin/myprogram"
    profile.flags.append("complain")
    
    rule1 = FileRule()
    rule1.path = "/etc/myprogram.conf"
    rule1.permissions = "r"
    
    rule2 = FileRule()
    rule2.path = "/var/log/myprogram.log"
    rule2.permissions = "rw"
    
    rule3 = FileRule()
    rule3.path = "/home/user/data"
    rule3.permissions = "rw"
    rule3.owner = True
    
    profile.rules.extend([rule1, rule2, rule3])
    policy.profiles.append(profile)
    
    print(policy)