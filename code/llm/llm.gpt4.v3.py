import re
import csv
import time
from openai import OpenAI

# Initialize OpenAI client
client = OpenAI(api_key="a vossa API KEY")


class DpkgLogParser:
    def __init__(self, log_file):
        self.log_file = log_file

    def extract_packages(self):
        packages = set()
        pattern = re.compile(
            r'(install|upgrade) ([\w\-\+\.]+):\w+ [^\s]+ ([\w\-\+\.]+)')

        with open(self.log_file, 'r', encoding='utf-8') as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    pkg_name = match.group(2)
                    pkg_version = match.group(3)
                    packages.add((pkg_name, pkg_version))
        return list(packages)


class VulnerabilityChecker:
    def __init__(self, model_name="gpt-4", batch_size=5):
        self.model_name = model_name
        self.batch_size = batch_size

    def query_gpt4(self, prompt, retries=3, delay=5):
        for attempt in range(retries):
            try:
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.2,
                    max_tokens=700
                )
                return response.choices[0].message.content
            except Exception as e:
                print(
                    f"Error querying GPT-4 (attempt {attempt + 1}/{retries}): {e}")
                time.sleep(delay)
        return None

    def check(self, packages):
        results = []
        for i in range(0, len(packages), self.batch_size):
            batch = packages[i:i+self.batch_size]
            batch_prompt = "You are a cybersecurity assistant. Check if the following Linux packages have known vulnerabilities.\n"
            for pkg_name, pkg_version in batch:
                batch_prompt += f"- Package: {pkg_name}, Version: {pkg_version}\n"
            batch_prompt += (
                "\nFormat the response strictly as:\n"
                "Package: [name], Vulnerable: [YES/NO], CVE: [CVE-ID or None], Description: [short summary or None].\n"
                "One line per package."
            )

            response = self.query_gpt4(batch_prompt)
            if response:
                lines = response.strip().splitlines()
                for line in lines:
                    match = re.search(
                        r'Package: (.+?), Vulnerable: (YES|NO), CVE: ([\w\-]+|None), Description: (.+)',
                        line,
                        re.IGNORECASE
                    )
                    if match:
                        results.append((
                            match.group(1).strip(),     # Package
                            match.group(2).upper(),     # Vulnerable
                            match.group(3).upper(),     # CVE
                            match.group(4).strip()      # Description
                        ))
                    else:
                        results.append(
                            ("UNKNOWN", "UNCLEAR", "NONE", "Parse error"))
            else:
                for pkg_name, _ in batch:
                    results.append((pkg_name, "ERROR", "NONE", "Query failed"))
        return results


class CSVReporter:
    def __init__(self, output_file):
        self.output_file = output_file

    def save(self, data):
        with open(self.output_file, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            for row in data:
                writer.writerow(row)


if __name__ == "__main__":
    log_path = 'C:\\Users\\Bruno\\Desktop\\DSI.Logs\\dpkg.log'
    output_csv = 'C:\\Users\\Bruno\\Desktop\\DSI.Logs\\gpt\\4\\vulnerability_report.csv'

    parser = DpkgLogParser(log_path)
    packages = parser.extract_packages()
    print(f"Extracted {len(packages)} packages.")

    checker = VulnerabilityChecker(batch_size=5)
    results = checker.check(packages)

    reporter = CSVReporter(output_csv)
    reporter.save(results)
    print(f"Report saved to {output_csv}")
