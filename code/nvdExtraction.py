
import time
import requests


def fetch_cves_for_package(package_name):
    # NVD API URL for CVE (version 2.0)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Search parameters
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key = "dbc90df4-2777-4c3c-99a3-9821c42729d3"
    results_per_page = 2000
    start_index = 0
    cve_objects = []

    try:
        while True:
            headers = {
                "apiKey": api_key  # API key goes in headers
            }
            params = {
                "keywordSearch": package_name,
                "resultsPerPage": results_per_page,
                "startIndex": start_index
            }
            # Make a request to the API
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()  # Verify if the request was successful

            # Convert to JSON
            data = response.json()

            total_results = data.get('totalResults', 0)

            # Filter CVE's that are related to the searched package
            cves = data.get('vulnerabilities', [])

            # List to store CVE objects
            cve_objects = []

            # Show found CVE's
            for cve in cves:
                cve_data = cve['cve']

                # Extract the information
                cve_id = cve_data['id']
                description = cve_data['descriptions'][0]['value']

                metrics = cve_data.get("metrics", {})
                cvss_data = {}

                for key in metrics:
                    if key.startswith("cvssMetric"):
                        metric_list = metrics[key]
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            break  # usamos apenas a primeira métrica encontrada

                severity = {
                    "cvssVersion": cvss_data.get('version'),
                    "baseScore": cvss_data.get('baseScore'),
                    "baseSeverity": cvss_data.get('baseSeverity'),
                    "cvssCode": cvss_data.get('vectorString')
                }
                references = cve_data['references']

                # Access CPE
                configurations = cve_data.get('configurations', [])
                cpe_list = []
                if configurations:
                    for node in configurations[0]['nodes']:
                        for cpe_match in node['cpeMatch']:
                            cpe_parts = cpe_match.get(
                                'criteria', '').split(':')
                            cpe_list.append({
                                "part": cpe_parts[1] if len(cpe_parts) > 1 else None,
                                "vendor": cpe_parts[3] if len(cpe_parts) > 3 else None,
                                "product": cpe_parts[4] if len(cpe_parts) > 4 else None,
                                "version": cpe_parts[5] if len(cpe_parts) > 5 else None,
                                "update": cpe_parts[6] if len(cpe_parts) > 6 else None,
                                "edition": cpe_parts[7] if len(cpe_parts) > 7 else None,
                                "language": cpe_parts[8] if len(cpe_parts) > 8 else None,
                                "sw_edition": cpe_parts[9] if len(cpe_parts) > 9 else None,
                                "target_sw": cpe_parts[10] if len(cpe_parts) > 10 else None,
                                "target_hw": cpe_parts[11] if len(cpe_parts) > 11 else None,
                                "other": cpe_parts[12] if len(cpe_parts) > 12 else None
                            })

                # Create the CVE object
                cve_object = {
                    "id": cve_id,
                    "description": description,
                    "severity": severity,
                    "references": references,
                    "cpe": cpe_list
                }

                # Add the object to the list
                cve_objects.append(cve_object)

            start_index += results_per_page
            if start_index >= total_results:
                break

            time.sleep(6)

            # Return the CVE objects list
        return cve_objects

    except requests.exceptions.HTTPError as e:
        print(f"❌ Erro HTTP: {e}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro na requisição: {e}")


def write_to_file(cve_list, output_file):
    with open(output_file, 'w', encoding='utf-8') as file:
        for cve in cve_list:
            file.write(f"CVE ID: {cve['id']}\n")
            file.write(f"Description: {cve['description']}\n")
            file.write(f"Severity:\n")
            file.write(
                f"  - CVSS Version: {cve['severity'].get('cvssVersion')}\n")
            file.write(f"  - Base Score: {cve['severity'].get('baseScore')}\n")
            file.write(
                f"  - Base Severity: {cve['severity'].get('baseSeverity')}\n")
            file.write(f"  - CVSS Vector: {cve['severity'].get('cvssCode')}\n")

            file.write("CPEs:\n")
            if cve['cpe']:
                for cpe in cve['cpe']:
                    file.write(
                        f"  - Vendor: {cpe.get('vendor')}, Product: {cpe.get('product')}, Version: {cpe.get('version')}\n")
            else:
                file.write("  - No CPE data available.\n")

            file.write("References:\n")
            for ref in cve['references']:
                file.write(f"  - {ref.get('url')}\n")

            file.write("\n" + "-"*60 + "\n\n")


if __name__ == "__main__":
    package_name = "linux"  # Name of the to be searched package
    cves = fetch_cves_for_package(package_name)
    write_to_file(cves, f"{package_name}_cves.txt")

    # Show CVE objects
    for cve in cves:
        print(cve)
