# %%
import re

# Function to process the log and create OTTR format
def parse_log_to_ottr(file_path):
    ottr_template = []

    # Open the log file and process each line
    with open(file_path, 'r') as file:
        for line in file:
            # Parse the log line using regular expressions
            match = re.match(r"(?P<timestamp>\S+ \S+) (?P<action>\S+) (?P<package>[\w-]+):(?P<architecture>\S+) (?P<version_old>\S+) (?P<version_new>\S+|<none>)", line)
            if match:
                timestamp = match.group("timestamp")
                action = match.group("action")
                package = match.group("package")
                architecture = match.group("architecture")
                version_old = match.group("version_old")
                version_new = match.group("version_new")
                
                # Construct OTTR template line
                ottr_template.append({
                    "timestamp": timestamp,
                    "action": action,
                    "package": package,
                    "architecture": architecture,
                    "version_old": version_old,
                    "version_new": version_new
                })
    
    return ottr_template

# Function to write OTTR output to a new file
def write_ottr_to_file(ottr_data, output_file):
    with open(output_file, 'w') as file:
        for entry in ottr_data:
            file.write(f"Timestamp: {entry['timestamp']} \nAction: {entry['action']} \nPackage: {entry['package']} \nArchitecture: {entry['architecture']} \nOld Version: {entry['version_old']} \nNew Version: {entry['version_new']}\n\n")

# Example usage
input_file = "dpkg.log"  # Replace with your actual log file path
output_file = "output_dpkg_template_by_line.txt"  # The file where the OTTR data will be written

# Parse the log file to OTTR format
ottr_data = parse_log_to_ottr(input_file)

# Write the OTTR data to a file
write_ottr_to_file(ottr_data, output_file)

print(f"Template has been written to {output_file}")

# %%
