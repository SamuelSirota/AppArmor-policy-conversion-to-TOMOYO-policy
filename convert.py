from lark import Lark
import os, sys
from transformer import AppArmorTransformer, preprocess_policy_file, convert_to_tomoyo

   
def main():
    if len(sys.argv) != 4:
        print("Usage: python convert.py apparmor_policy domain_policy exception_policy")
        sys.exit(1)

    apparmor_file = sys.argv[1]
    domain_file = sys.argv[2]
    exception_file = sys.argv[3]

    print("Argument 1:", apparmor_file)
    print("Argument 2:", domain_file)
    print("Argument 3:", exception_file)
    
    with open("apparmor.lark", "r") as f:
        grammar = f.read()
    parser = Lark(grammar, start="start", parser="lalr")
    folder_path = os.getcwd()

    try:
        print(f"File: {apparmor_file}")
        print("-------- Preprocessing --------")
        preprocessed_text = preprocess_policy_file(
            filepath=apparmor_file,
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
        with open(domain_file, "w") as f:
            f.write(domain_lines)
        with open(exception_file, "w") as f:
            f.write(exception_lines)
        print(f"Domain policy written to {domain_file}")
        print(f"Exception policy written to {exception_file}")
    except Exception as e:
        print("An exception occurred")
        print(e)
    finally:
        print("■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■")

if __name__ == "__main__":
    main()