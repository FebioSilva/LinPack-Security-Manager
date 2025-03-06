import re
from datetime import datetime
from collections import defaultdict

class DpkgLogParser:
    def __init__(self, log_path="resources/dpkg.log"):
        self.log_path = log_path
        self.entries = []
        self.parse_log()

    def parse_log(self):
        pattern = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\S+) (\S+): (\S+)")
        try:
            with open(self.log_path, "r", encoding="utf-8") as log_file:
                for line in log_file:
                    match = pattern.match(line)
                    if match:
                        date, time, process, action, package = match.groups()
                        timestamp = datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S")
                        self.entries.append({
                            "timestamp": timestamp,
                            "process": process,
                            "action": action,
                            "package": package,
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
    print("Installed packages:", parser.get_entries("install"))
