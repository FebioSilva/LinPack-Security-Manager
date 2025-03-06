import re
from datetime import datetime
from collections import defaultdict

class DpkgLogParser:
    def __init__(self, log_path):
        self.log_path = log_path
        self.entries = []
        self.parse_log()

    def parse_log(self):
        fpattern = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\S+) (\S+):(\S+) (\S+)")
        spattern = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\S+) (\S+) (\S+):(\S+) (\S+)")
        try:
            with open(self.log_path, "r", encoding="utf-8") as log_file:
                for line in log_file:
                    match = fpattern.match(line)
                    if match:
                        date, time, action, package_name, package_arch, version = match.groups()
                        timestamp = datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S")
                        self.entries.append({
                            "timestamp": timestamp,
                            "action": action,
                            "package_name": package_name,
                            "package_arch": package_arch,
                            "version": version
                        })
                    else:
                        smatch = spattern.match(line)
                        if smatch:
                            date, time, action, state, package_name, package_arch, version = smatch.groups()
                            timestamp = datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S")
                            self.entries.append({
                                "timestamp": timestamp,
                                "action": action,
                                "state": state,
                                "package_name": package_name,
                                "package_arch": package_arch,
                                "version": version
                            })    
                    
        except FileNotFoundError:
            print(f"Error: Log file '{self.log_path}' not found.")

    def get_entries(self, action=None):
        if action:
            return [entry for entry in self.entries if entry["action"] == action]
        return self.entries

    def get_summary(self):
        summary = defaultdict(int)
        for entry in self.entries:
            summary[entry["action"]] += 1
        return dict(summary)

# Example usage
if __name__ == "__main__":
    parser = DpkgLogParser("dpkg.log")
    print("Summary of actions:", parser.get_summary())
    print("Removed packages:", parser.get_entries("remove"))