from datetime import datetime, timedelta
import time
import requests


def is_linux_cpe(cpe):
    vendor = (cpe.get('vendor') or '').lower()
    product = (cpe.get('product') or '').lower()
    target_hw = (cpe.get('target_hw') or '').lower()

    linux_vendors = ['debian', 'canonical', 'redhat',
                     'fedoraproject', 'suse', 'oracle', 'linux']
    linux_products = ['debian_linux', 'ubuntu_linux', 'red_hat_enterprise_linux',
                      'fedora', 'suse_linux', 'oracle_linux', 'linux_kernel']

    if vendor in linux_vendors or product in linux_products or target_hw == 'linux_kernel':
        return True
    return False


def fetch_cves_for_package(start_date, end_date):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    api_key = "dbc90df4-2777-4c3c-99a3-9821c42729d3"
    results_per_page = 2000
    cve_objects = []

    current_start = start_date
    while current_start < end_date:
        current_end = min(current_start + timedelta(days=119), end_date)
        start_index = 0
        print(f"current_start: {current_start}, current_end: {current_end}")

        while True:
            headers = {"apiKey": api_key, "User-Agent": "linpack-script/1.0"}
            params = {
                "resultsPerPage": results_per_page,
                "startIndex":     start_index,
                "pubStartDate":   current_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate":     current_end.strftime("%Y-%m-%dT%H:%M:%S.999"),
            }

            resp = requests.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()

            total_results = data.get("totalResults", 0)
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln["cve"]

                # --------- extrai CPEs ---------
                cpe_list = []
                for cfg in cve_data.get("configurations", []):
                    for node in cfg.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            parts = match["criteria"].split(":")
                            cpe_list.append({
                                "vendor":  parts[3] if len(parts) > 3 else "unknown_vendor",
                                "product": parts[4] if len(parts) > 4 else "unknown_product",
                                "version": parts[5] if len(parts) > 5 else "unknown_version",
                                "startVersion": match.get("versionStartIncluding"),
                                "endVersion":   match.get("versionEndExcluding"),
                                "target_hw": parts[11] if len(parts) > 11 else ""
                            })

                # filtra só Linux
                if not any(is_linux_cpe(cpe) for cpe in cpe_list):
                    continue

                # --------- descrição ---------
                descs = cve_data.get("descriptions", [])
                description = descs[0]["value"] if descs else ""

                # --------- severidade ---------
                cvss_data = {}
                for k, lst in cve_data.get("metrics", {}).items():
                    if k.startswith("cvssMetric") and lst:
                        cvss_data = lst[0].get("cvssData", {})
                        break
                severity = {
                    "cvssVersion": cvss_data.get("version"),
                    "baseScore":   cvss_data.get("baseScore"),
                    "baseSeverity": cvss_data.get("baseSeverity"),
                    "cvssCode":    cvss_data.get("vectorString")
                }

                # --------- monta objeto final ---------
                cve_objects.append({
                    "id":          cve_data["id"],
                    "description": description,
                    "severity":    severity,
                    "references":  cve_data.get("references", []),
                    "cpe":         cpe_list
                })

            start_index += results_per_page
            if start_index >= total_results:
                break
            time.sleep(6)   # respeitar rate-limit

        current_start = current_end + timedelta(seconds=1)

    return cve_objects


def write_to_file(cve_list, output_file):
    with open(output_file, 'w', encoding='utf-8') as file:
        for cve in cve_list:
            file.write(f"CVE ID: {cve.get('id')}\n")
            descriptions = cve.get('descriptions', [])
            description_text = descriptions[0]['value'] if descriptions else 'No description'
            file.write(f"Description: {description_text}\n")

            metrics = cve.get('metrics', {})
            cvss_data = {}
            for key in metrics:
                if key.startswith('cvssMetric'):
                    metric_list = metrics[key]
                    if metric_list:
                        cvss_data = metric_list[0].get('cvssData', {})
                        break

            file.write("Severity:\n")
            file.write(f"  - CVSS Version: {cvss_data.get('version')}\n")
            file.write(f"  - Base Score: {cvss_data.get('baseScore')}\n")
            file.write(f"  - Base Severity: {cvss_data.get('baseSeverity')}\n")
            file.write(f"  - CVSS Vector: {cvss_data.get('vectorString')}\n")

            file.write("CPEs:\n")
            cpes = cve.get('filtered_cpes', [])
            if cpes:
                for cpe in cpes:
                    file.write(
                        f"  - Vendor: {cpe.get('vendor')}, Product: {cpe.get('product')}, Version: {cpe.get('version')}, Target HW: {cpe.get('target_hw')}\n"
                    )
            else:
                file.write("  - No CPE data available.\n")

            references = cve.get('references', [])
            file.write("References:\n")
            for ref in references:
                file.write(f"  - {ref.get('url')}\n")

            file.write("\n" + "-" * 60 + "\n\n")


if __name__ == "__main__":
    start_date = datetime(2020, 1, 1)
    end_date = datetime(2025, 12, 31)

    cves = fetch_cves_for_package(start_date, end_date)
    print(f"Total CVEs Linux-related fetched: {len(cves)}")

    # write_to_file(cves, "linux_related_cves.txt")
