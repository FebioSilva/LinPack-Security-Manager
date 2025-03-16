# %%
import re

class LogParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.ottr_template = []
        self.event_id = 1  # Initialize event ID

    def parse_log(self):
        # Open the log file and process each line
        with open(self.file_path, 'r') as file:
            for line in file:
                # Parse the log line using regular expressions
                match = re.match(r"(?P<timestamp>\S+ \S+) (?P<action>\S+) (?P<package>[\w-]+):(?P<architecture>\S+) (?P<version_old>\S+) (?P<version_new>\S+|<none>)", line)
                if match:
                    self.ottr_template.append({
                        "event_id": self.event_id,
                        "timestamp": match.group("timestamp"),
                        "action": match.group("action"),
                        "package": match.group("package"),
                        "architecture": match.group("architecture"),
                        "version_old": match.group("version_old"),
                        "version_new": match.group("version_new"),
                        "event": line.strip()
                    })
                    self.event_id += 1  # Increment event ID for next entry

    def write_to_file(self, output_file):
        with open(output_file, 'w') as file:
            for entry in self.ottr_template:
                file.write(f"Event ID: {entry['event_id']} \nTimestamp: {entry['timestamp']} \nAction: {entry['action']} \nPackage: {entry['package']} \nArchitecture: {entry['architecture']} \nOld Version: {entry['version_old']} \nNew Version: {entry['version_new']}\nEvent: {entry['event']}\n\n")
    
    def write_to_rdf(self, rdf_output_file):
        with open(rdf_output_file, 'w') as file:
            file.write("PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n")
            file.write("PREFIX log: <https://w3id.org/sepses/ns/log#>\n\n")
            for entry in self.ottr_template:
                file.write(f"log:Event_{entry['event_id']} a :Event ;\n")
                file.write(f"\tlog:Timestamp \"{entry['timestamp']}\" ;\n")
                file.write(f"\tlog:Type \"Action\" ;\n")
                file.write(f"\tlog:State \"{entry['action']}\" ;\n")
                file.write(f"\tlog:Package \"{entry['package']}\" ;\n")
                file.write(f"\tlog:Architecture \"{entry['architecture']}\" ;\n")
                file.write(f"\tlog:OldVersion \"{entry['version_old']}\" ;\n")
                file.write(f"\tlog:NewVersion \"{entry['version_new']}\" ;\n")
                file.write(f"\tlog:Event \"{entry['event']}\" .\n\n")

    def write_to_sparql(self, sparql_output_file):
        with open(sparql_output_file, 'w') as file:
            file.write("PREFIX log: <https://w3id.org/sepses/ns/log#>\n")
            file.write("INSERT DATA {\n")
            for entry in self.ottr_template:
                file.write(f"  log:Event_{entry['event_id']} a log:Event ;\n")
                file.write(f"    log:Timestamp \"{entry['timestamp']}\" ;\n")
                file.write(f"    log:Type \"Action\" ;\n")
                file.write(f"    log:State \"{entry['action']}\" ;\n")
                file.write(f"    log:Package \"{entry['package']}\" ;\n")
                file.write(f"    log:Architecture \"{entry['architecture']}\" ;\n")
                file.write(f"    log:OldVersion \"{entry['version_old']}\" ;\n")
                file.write(f"    log:NewVersion \"{entry['version_new']}\" ;\n")
                file.write(f"    log:Event \"{entry['event']}\" .\n")
            file.write("}\n")

# Example usage
input_file = "dpkg.log"  # Replace with your actual log file path
output_file = "output_dpkg_template_by_line.txt"  # The file where the OTTR data will be written
rdf_output_file = "output_dpkg_template.ttl"  # The file where RDF Turtle data will be written
sparql_output_file = "insert_data.sparql"  # The file where SPARQL INSERT statements will be written

parser = LogParser(input_file)
parser.parse_log()
parser.write_to_file(output_file)
parser.write_to_rdf(rdf_output_file)
parser.write_to_sparql(sparql_output_file)

print(f"Template has been written to {output_file}")
print(f"RDF Turtle format has been written to {rdf_output_file}")
print(f"SPARQL INSERT statements have been written to {sparql_output_file}")
