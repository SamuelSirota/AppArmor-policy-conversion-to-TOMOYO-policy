from lark import Lark, Transformer, v_args
import os
# Load the grammar
with open("apparmor.lark", "r") as f:
    grammar = f.read()

class AccessTransformer(Transformer):
    def exclude_w_a_combination(self, items):
        
        access_list = [item[0] for item in items]
        
        if 'w' in access_list and 'a' in access_list:
            raise ValueError("Access sequence cannot contain both 'w' and 'a'.")
        return access_list

parser = Lark(grammar, start="start", parser="lalr")
folder_path = "/home/samos/FEI/ING/year2/diplomovka/tests/fails/"



for filename in os.listdir(folder_path):
    print(filename)
    file_path = os.path.join(folder_path, filename)

    if os.path.isfile(file_path):
        with open(file_path, "r") as f:
            policy = f.read()
        try:
            tree = parser.parse(policy)
            print(tree.pretty())
        except Exception as e:
            print("An exception occurred")
            print(e)
    
