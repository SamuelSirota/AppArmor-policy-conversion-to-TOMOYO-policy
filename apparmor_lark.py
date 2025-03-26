from lark import Lark

# Load the grammar
with open("apparmor.lark", "r") as f:
    grammar = f.read()

parser = Lark(grammar, start="start", parser="lalr")

# Example policy
try:
    with open("tests/passes/variable.sd", "r") as f:
        policy = f.read()
    tree = parser.parse(policy)
    print(tree.pretty())
except Exception as e:
    print("An exception occurred")
    print(e)
    
