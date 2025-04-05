# %%
import re

class LogParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.parsed_logs = []
        self.log_id = 1  # Initialize log ID

    def parse_log(self):
        # Open the log file and process each line
        with open(self.file_path, 'r') as file:
            for line in file:
                # Match dpkg action logs
                action_match = re.match(r"(?P<timestamp>\S+ \S+) (?P<action>install|upgrade|remove) (?P<package>[\w-]+):(?P<architecture>\S+) (?P<version_old>\S+) (?P<version_new>\S+|<none>)", line)
                
                # Match dpkg state logs
                state_match = re.match(r"(?P<timestamp>\S+ \S+) status (?P<state>[\w-]+) (?P<package>[\w-]+):(?P<architecture>\S+) (?P<version>\S+)", line)
                
                if action_match:
                    self.parsed_logs.append({
                        "log_id": self.log_id,
                        "timestamp": action_match.group("timestamp"),
                        "type": "action",
                        "action": action_match.group("action"),
                        "package": action_match.group("package"),
                        "architecture": action_match.group("architecture"),
                        "version_old": action_match.group("version_old"),
                        "version_new": action_match.group("version_new"),
                    })
                elif state_match:
                    self.parsed_logs.append({
                        "log_id": self.log_id,
                        "timestamp": state_match.group("timestamp"),
                        "type": "state",
                        "state": state_match.group("state"),
                        "package": state_match.group("package"),
                        "architecture": state_match.group("architecture"),
                        "version": state_match.group("version"),
                    })
                else:
                    continue
                
                self.log_id += 1  # Increment log ID for next entry

    def write_to_file(self, output_file):
        with open(output_file, 'w') as file:
            for entry in self.parsed_logs:
                if entry["type"] == "action":
                    file.write(f"Event ID: {entry['log_id']}\nTimestamp: {entry['timestamp']}\nType: Action\nAction: {entry['action']}\nPackage: {entry['package']}\nArchitecture: {entry['architecture']}\nOld Version: {entry['version_old']}\nNew Version: {entry['version_new']}\n\n")
                else:
                    file.write(f"Event ID: {entry['log_id']}\nTimestamp: {entry['timestamp']}\nType: State\nState: {entry['state']}\nPackage: {entry['package']}\nArchitecture: {entry['architecture']}\nVersion: {entry['version']}\n\n")

# Example usage
input_file = "../resources/dpkg.log"  # Replace with your actual log file path
output_file = "output_dpkg_template_by_line.txt"  # The file where parsed logs will be written

parser = LogParser(input_file)
parser.parse_log()
parser.write_to_file(output_file)

print(f"Parsed log has been written to {output_file}")
# %%
