import re


class LogParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.parsed_logs = []
        self.log_id = 1

    def parse_log(self):
        with open(self.file_path, 'r') as file:
            for line in file:
                line = line.strip()

                # Match action logs (install, upgrade, remove)
                action_match = re.match(
                    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<action>install|upgrade|remove|purge|configure|unpack|triggered|trigproc|trigawait) (?P<package>[\w\-\.\+]+)(?:\s*:\s*(?P<architecture>[\w\d\-]+) (?P<version_old><none>|[^\s]+)\s*(?P<version_new><none>|[^\s]+)?)",
                    line
                )

                # Match state logs
                state_match = re.match(
                    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) status (?P<state>[\w-]+) (?P<package>[\w\-\.\+]+):(?P<architecture>[\w\d\-]+) (?P<version>[\w\.\-\~:]+)",
                    line
                )

                # Match conffile logs
                conffile_match = re.match(
                    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) conffile (?P<filepath>.+?) (?P<decision>\w+)",
                    line
                )

                # Match startup logs
                startup_match = re.match(
                    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) startup (?P<context>\w+) (?P<command>\w+)",
                    line
                )

                # Check and store matches
                if action_match:
                    action = action_match.group("action")
                    if action == "install":
                        self.parsed_logs.append({
                            "log_id": self.log_id,
                            "timestamp": action_match.group("timestamp").replace(" ", "T"),
                            "type": "action",
                            "action": action_match.group("action"),
                            "package": action_match.group("package"),
                            "architecture": action_match.group("architecture"),
                            "version": action_match.group("version_new")
                        })

                    elif action == "upgrade":
                        self.parsed_logs.append({
                            "log_id": self.log_id,
                            "timestamp": action_match.group("timestamp").replace(" ", "T"),
                            "type": "action",
                            "action": action_match.group("action"),
                            "package": action_match.group("package"),
                            "architecture": action_match.group("architecture"),
                            "version": action_match.group("version_new"),
                            "replace": action_match.group("version_old")
                        })

                    elif action == "remove" or action == "purge":
                        self.parsed_logs.append({
                            "log_id": self.log_id,
                            "timestamp": action_match.group("timestamp").replace(" ", "T"),
                            "type": "action",
                            "action": action_match.group("action"),
                            "package": action_match.group("package"),
                            "architecture": action_match.group("architecture"),
                            "version": action_match.group("version_old")
                        })

                    else:
                        self.parsed_logs.append({
                            "log_id": self.log_id,
                            "timestamp": action_match.group("timestamp").replace(" ", "T"),
                            "type": "action",
                            "action": action_match.group("action"),
                            "package": action_match.group("package"),
                            "architecture": action_match.group("architecture"),
                            "version": action_match.group("version_old")
                        })

                elif state_match:
                    self.parsed_logs.append({
                        "log_id": self.log_id,
                        "timestamp": state_match.group("timestamp").replace(" ", "T"),
                        "type": "state",
                        "state": state_match.group("state"),
                        "package": state_match.group("package"),
                        "architecture": state_match.group("architecture"),
                        "version": state_match.group("version"),
                    })

                elif conffile_match:
                    self.parsed_logs.append({
                        "log_id": self.log_id,
                        "timestamp": conffile_match.group("timestamp").replace(" ", "T"),
                        "type": "conffile",
                        "filepath": conffile_match.group("filepath").strip(),
                        "decision": conffile_match.group("decision"),
                    })

                elif startup_match:
                    self.parsed_logs.append({
                        "log_id": self.log_id,
                        "timestamp": startup_match.group("timestamp").replace(" ", "T"),
                        "type": "startup",
                        "context": startup_match.group("context"),
                        "command": startup_match.group("command"),
                    })

                else:
                    continue

                self.log_id += 1

    def write_to_file(self, output_file):
        with open(output_file, 'w') as file:
            for entry in self.parsed_logs:
                file.write(
                    f"Event ID: {entry['log_id']}\nTimestamp: {entry['timestamp']}\nType: {entry['type'].capitalize()}\n")

                if entry["type"] == "action":
                    file.write(
                        f"Action: {entry['action']}\nPackage: {entry['package']}\nArchitecture: {entry['architecture']}\nOld Version: {entry['version_old']}\nNew Version: {entry['version_new']}\n")

                elif entry["type"] == "state":
                    file.write(
                        f"State: {entry['state']}\nPackage: {entry['package']}\nArchitecture: {entry['architecture']}\nVersion: {entry['version']}\n")

                elif entry["type"] == "conffile":
                    file.write(
                        f"File: {entry['filepath']}\nAction: {entry['action']}\n")

                elif entry["type"] == "startup":
                    file.write(
                        f"Context: {entry['context']}\nAction: {entry['action']}\n")

                file.write("\n")  # Add a blank line between entries


# Exemplo de uso
if __name__ == "__main__":
    # Change it for the real path to the dpkg.log file
    input_file = "../resources/dpkg.log"

    parser = LogParser(input_file)
    parser.parse_log()
    parsed_logs = parser.parsed_logs  # Get parsed logs for further processing
    print("Parsed logs:")
    installed_logs = [log for log in parsed_logs if log["type"] == "action" and log["action"] == "install"]
    print(parsed_logs)  # Print parsed logs for debugging
