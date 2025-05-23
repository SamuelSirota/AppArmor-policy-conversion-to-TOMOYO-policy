# Master thesis - conversion of AppArmor policy to TOMOYO policy

[![Python 3.13.2](https://img.shields.io/badge/python-3.13.2-purple.svg)](https://www.python.org/downloads/release/python-3132/)
[![Static Badge](https://img.shields.io/badge/Lark-1.2.2-purple)](https://github.com/lark-parser/lark/releases/tag/1.2.2)

## Description

This repository contains a python script which converts AppArmor policy to TOMOYO policy. We use the Lark parsing library for parsing.

## Quick start

To run the script, you need to have Python and Lark library installed. You can install Lark using pip:

```bash
pip install lark --upgrade
```

To run the script, you can use the following command:

```bash
python convert.py <input_file> <domain_policy> <exception_policy>
```

Where:

- `<input_file>` is the path to the AppArmor policy file you want to convert.
- `<domain_policy>` is the path where the TOMOYO domain policy file will be saved.
- `<exception_policy>` is the path where the TOMOYO exception policy file will be saved.

All three files are required. The script will parse the AppArmor policy file and generate TOMOYO policy files in the specified paths.

To use the policy files, you need to load them into TOMOYO.
If you do not have TOMOYO installed, you can follow the instructions in the [TOMOYO installation guide](notes/tomoyo_install.md). When you have TOMOYO installed, you can load the generated policy files into TOMOYO.
You can load them using `tomoyo-loadpolicy` command:

```bash
tomoyo-loadpolicy -d < domain_policy
tomoyo-loadpolicy -e < exception_polcy
```

Arguments `-d` and `-e` are used to append domain and exception policy files respectively.

When everything is set up, you can start the TOMOYO policy manager using:

```bash
tomoyo-editpolicy
```

This will open the TOMOYO policy manager, where you can manage the policies and monitor the system calls made by applications.

## Structure

```bash
Repo
├── notes/
├── tests/
│   ├── man_test/
│   │   ├── DOMAIN
│   │   ├── EXCEPTION
│   │   ├── PYTHON_KNIZNICE
│   │   ├── debug/
│   │   ├── deny_flat_paths.txt
│   │   ├── file_operation_report.txt
│   │   ├── man_flat_paths.txt
│   │   ├── results/
│   │   │   ├── apparmor_report.txt
│   │   │   ├── compared_results.txt
│   │   │   ├── report_converter.py
│   │   │   └── tomoyo_report.txt
│   │   ├── testing_helper.py
│   │   └── usr.bin.man
│   ├── fails/
│   └── passes/
├── apparmor.lark
├── convert.py
├── envs
├── testing.py
└── transformer.py
```

The main script is `convert.py`, which contains the main function. The `transformer.py` file contains the logic for transforming the parsed data into TOMOYO policy format. It uses the grammar defined in `apparmor.lark` to parse the AppArmor policy files.
The `envs` file contains the environment files used for testing.

The `notes/` directory contains notes and TODOs related to the project.
The `tests/fails/` and `tests/passes/` directories contain test cases and test data used while developing the conversion process.

The `testing.py` file contains the tests for testing the generated TOMOYO policy and the original AppArmor policy.
File `usr.bin.man` is the AppArmor policy used in testing.
The `tests/man_test/` directory contains the files used for testing. It contains the `DOMAIN`, `EXCEPTION`, and `PYTHON_KNIZNICE` files, which are loaded to TOMOYO. The `deny_flat_paths.txt` and `man_flat_paths.txt` contain the individual file accesses used in testing.
In the `tests/man_test/results/` directory, the `report_converter.py` file is used to combine the results from both AppArmor (`apparmor_report.txt`) and TOMOYO (`tomoyo_report.txt`).
