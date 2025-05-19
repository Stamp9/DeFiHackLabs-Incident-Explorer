import subprocess
import json
import os
import re
from normalize_attack import normalize_attack_type

REPO_MAIN_PATH = "main_repo"
COMMIT_TRACK_FILE = ".last_repo_main_commit"
INCIDENTS_FILE = "incidents.json"

# Check if current commit file exists
if not os.path.exists("repo_main_current_commit.txt"):
    print("Error: repo_main_current_commit.txt not found.")
    exit(1)

with open("repo_main_current_commit.txt", "r") as f:
    current_commit = f.read().strip()

# Handle first run scenario
if os.path.exists(COMMIT_TRACK_FILE):
    with open(COMMIT_TRACK_FILE, "r") as f:
        last_commit = f.read().strip()
else:
    # For first run, get the commit before the current one
    try:
        last_commit = subprocess.check_output(
            [
                "git",
                "-C",
                REPO_MAIN_PATH,
                "rev-parse",
                f"{current_commit}~1",  # Get parent commit
            ],
            text=True,
        ).strip()
    except subprocess.CalledProcessError:
        # If there's no parent commit, use the current commit
        last_commit = current_commit

if last_commit == current_commit:
    with open(COMMIT_TRACK_FILE, "w") as f:
        f.write(current_commit)
    print("No new commits to diff.")
    exit(0)

print(f"Diffing between commits: {last_commit} and {current_commit}")

diff_output = subprocess.check_output(
    [
        "git",
        "-C",
        REPO_MAIN_PATH,
        "diff",
        f"{last_commit}..{current_commit}",
        "--",
        "README.md",
    ],
    text=True,
)

# Log the diff output for debugging
print(f"Diff output length: {len(diff_output)} characters")
print("First 500 characters of diff:")
print(diff_output[:500] + ("..." if len(diff_output) > 500 else ""))

lines = [
    line[1:].strip()
    for line in diff_output.splitlines()
    if line.startswith("+") and not line.startswith("+++")
]

blocks = []
block = []
for line in lines:
    if re.match(r"^\d{8}\s+\w+", line) and block:
        blocks.append(block)
        block = [line]
    else:
        block.append(line)
if block:
    blocks.append(block)

if os.path.exists(INCIDENTS_FILE):
    with open(INCIDENTS_FILE, "r") as f:
        incidents = json.load(f)
else:
    incidents = []

existing_set = {json.dumps(i, sort_keys=True) for i in incidents}
new_entries = 0

for block in blocks:
    if len(block) < 3:
        continue
    try:
        date_line = block[0]
        lost_line = next(l for l in block if l.lower().startswith("lost:"))
        contract_line = next((l for l in block if l.endswith(".sol")), "")

        date_match = re.match(r"^(\d{8})\s+(\w+)\s*-\s*(.+)$", date_line)
        if not date_match:
            continue

        date, name, raw_type = date_match.groups()
        raw_type = raw_type.strip()
        attack_type = normalize_attack_type(raw_type)

        lost_match = re.match(r"Lost:\s*([\d,.]+)\s*([A-Z]{2,5})", lost_line)
        if not lost_match:
            continue
        lost = float(lost_match.group(1).replace(",", ""))
        loss_type = lost_match.group(2)

        contract_path_match = re.search(r"(src/[^\s]+\.sol)", " ".join(block))
        contract_path = (
            contract_path_match.group(1)
            if contract_path_match
            else contract_line.strip()
        )

        incident = {
            "date": date,
            "name": name,
            "type": attack_type,
            "Lost": lost,
            "lossType": loss_type,
            "Contract": contract_path,
        }

        key = json.dumps(incident, sort_keys=True)
        if key not in existing_set:
            incidents.append(incident)
            new_entries += 1
    except Exception as e:
        print(f"Failed to parse block: {block}\n{e}")
        continue

if new_entries:
    with open(INCIDENTS_FILE, "w") as f:
        json.dump(incidents, f, indent=4)
    print(f"✅ Added {new_entries} new incidents.")
else:
    print("✅ No new incidents found.")

with open(COMMIT_TRACK_FILE, "w") as f:
    f.write(current_commit)
