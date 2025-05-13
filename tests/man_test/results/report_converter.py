import re
from tabulate import tabulate


def parse_report(content):
    access_dict = {}
    for line in content.splitlines():
        line = line.strip()
        match = re.match(r"^(read|write)\s+(\S+)\s+(Allowed|Denied|None)$", line)
        if match:
            access, path, status = match.groups()
            access_dict[(access, path)] = status
    return access_dict


def merge_logs(aa_data, tomoyo_data):
    all_keys = set(aa_data.keys()).union(tomoyo_data.keys())
    merged = []

    for key in all_keys:
        access, path = key
        aa_status = aa_data.get(key, "None")
        tomoyo_status = tomoyo_data.get(key, "None")

        # Skip if both are "None"

        if aa_status == "None" and tomoyo_status == "None":
            continue
        merged.append((access, path, aa_status, tomoyo_status))
    # Sort by AppArmor Access: Allowed < Denied < None

    sort_order = {"Allowed": 0, "Denied": 1, "None": 2}
    merged.sort(key=lambda x: (sort_order.get(x[2], 3), x[1]))
    return merged


# Load the two reports

with open("apparmor_report.txt") as f1, open("tomoyo_report.txt") as f2:
    apparmor_content = f1.read()
    tomoyo_content = f2.read()
# Parse the logs

apparmor_data = parse_report(apparmor_content)
tomoyo_data = parse_report(tomoyo_content)

# Merge and sort

merged_result = merge_logs(apparmor_data, tomoyo_data)

# Display as table

print(
    tabulate(
        merged_result, headers=["Access", "Path", "AppArmor Access", "TOMOYO Access"]
    )
)
