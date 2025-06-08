from datetime import datetime, timedelta
import time
import requests


# ─────────────────────────────
#  Utils – Linux filter & CPE
# ─────────────────────────────

def is_linux_cpe(cpe):
    """Return True if the CPE refers to a Linux distribution or the Linux
    kernel, False otherwise."""
    vendor = (cpe.get("vendor") or "").lower()
    product = (cpe.get("product") or "").lower()
    target_hw = (cpe.get("target_hw") or "").lower()

    linux_vendors = {
        "debian", "canonical", "redhat",
        "fedoraproject", "suse", "oracle", "linux",
    }
    linux_products = {
        "debian_linux", "ubuntu_linux", "red_hat_enterprise_linux",
        "fedora", "suse_linux", "oracle_linux", "linux_kernel",
    }

    return (
        vendor in linux_vendors or
        product in linux_products or
        target_hw == "linux_kernel"
    )


# ─────────────────────────────
#  Step 1 – Fetch CVEs from NVD
# ─────────────────────────────

def fetch_cves_for_package(start_date: datetime, end_date: datetime):
    """Download CVEs from the NVD API 2.0 within a date window and return a
    list of Python dicts already filtered down to Linux-related CPEs."""

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    api_key = "dbc90df4-2777-4c3c-99a3-9821c42729d3"
    results_per_page = 2000
    cve_objects = []

    current_start = start_date
    while current_start < end_date:
        current_end = min(current_start + timedelta(days=119), end_date)
        start_index = 0
        print(f"[*] Window: {current_start:%Y-%m-%d} → {current_end:%Y-%m-%d}")

        while True:
            headers = {"apiKey": api_key, "User-Agent": "linpack-script/1.0"}
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
                "pubStartDate": current_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": current_end.strftime("%Y-%m-%dT%H:%M:%S.999"),
            }

            resp = requests.get(url, headers=headers,
                                params=params, timeout=60)
            resp.raise_for_status()
            data = resp.json()

            total_results = data.get("totalResults", 0)
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln["cve"]

                # ─── CPEs with Versions handling ──────────────────────────────
                cpe_list = []
                for cfg in cve_data.get("configurations", []):
                    for node in cfg.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            parts = match["criteria"].split(":")
                            vendor = parts[3] if len(
                                parts) > 3 else "unknown_vendor"
                            product = parts[4] if len(
                                parts) > 4 else "unknown_product"
                            version = parts[5] if len(
                                parts) > 5 else "unknown_version"
                            target_hw = parts[11] if len(parts) > 11 else ""

                            start_incl = match.get("versionStartIncluding")
                            start_excl = match.get("versionStartExcluding")
                            end_incl = match.get("versionEndIncluding")
                            end_excl = match.get("versionEndExcluding")

                            versions_intervals = []

                            # Se versão é '*', tenta extrair intervalos reais
                            if version == "*":
                                # Prioriza versionStartIncluding / versionEndIncluding, depois os exclusivos
                                min_v = start_incl or start_excl or None
                                max_v = end_incl or end_excl or None

                                if min_v or max_v:
                                    versions_intervals.append({
                                        "min": min_v,
                                        "max": max_v,
                                        "label": None,
                                    })
                                else:
                                    # Se não tem intervalos, marcar como all versions
                                    versions_intervals.append({
                                        "min": None,
                                        "max": None,
                                        "label": "versions_all",
                                    })

                            elif version in ("-", "", None):
                                # Sem versão — não cria nenhum intervalo
                                pass
                            else:
                                # Se existe intervalo explícito, cria-o
                                if start_incl or start_excl or end_incl or end_excl:
                                    min_v = start_incl or start_excl
                                    max_v = end_incl or end_excl
                                    versions_intervals.append({
                                        "min": min_v,
                                        "max": max_v,
                                        "label": None,
                                    })
                                else:
                                    # Versão única (min e max iguais ao version)
                                    versions_intervals.append({
                                        "min": version,
                                        "max": version,
                                        "label": None,
                                    })

                            # Caso nenhum intervalo criado, cria entrada sem versão
                            if not versions_intervals:
                                cpe_list.append({
                                    "vendor": vendor,
                                    "product": product,
                                    "version_intervals": [],  # nenhum intervalo
                                    "target_hw": target_hw,
                                })
                            else:
                                for interval in versions_intervals:
                                    cpe_list.append({
                                        "vendor": vendor,
                                        "product": product,
                                        "version_intervals": [interval],
                                        "target_hw": target_hw,
                                    })

                # Filtra só CVEs que tocam targets Linux
                if not any(is_linux_cpe(cpe) for cpe in cpe_list):
                    continue

                # ─── description ───────────────────────────────────────────
                descs = cve_data.get("descriptions", [])
                description = descs[0]["value"] if descs else ""

                # ─── severity / CVSS ───────────────────────────────────────
                cvss_data = {}
                for k, lst in cve_data.get("metrics", {}).items():
                    if k.startswith("cvssMetric") and lst:
                        cvss_data = lst[0].get("cvssData", {})
                        break
                severity = {
                    "cvssVersion": cvss_data.get("version"),
                    "baseScore": cvss_data.get("baseScore"),
                    "baseSeverity": cvss_data.get("baseSeverity"),
                    "cvssCode": cvss_data.get("vectorString"),
                }

                # ─── Final object ──────────────────────────────────────────
                cve_objects.append({
                    "id": cve_data["id"],
                    "description": description,
                    "severity": severity,
                    "references": cve_data.get("references", []),
                    "cpe": cpe_list,
                    "pubDate": datetime.fromisoformat(cve_data["published"]) if "published" in cve_data else None,
                })

            start_index += results_per_page
            if start_index >= total_results:
                break
            time.sleep(6)

        current_start = current_end + timedelta(seconds=1)

    return cve_objects


# ──────────────────────────────────
#  (Opcional) – dump simples p/ TXT
# ──────────────────────────────────

def write_to_file(cve_list, output_file):
    """Grava as CVEs num ficheiro de texto human‑readable (debug/log)."""
    with open(output_file, "w", encoding="utf‑8") as fh:
        for cve in cve_list:
            fh.write(f"CVE ID: {cve['id']}\n")
            fh.write(f"Description: {cve['description']}\n")
            sev = cve["severity"]
            fh.write("Severity:\n")
            fh.write(f"  ‑ CVSS Version: {sev.get('cvssVersion')}\n")
            fh.write(f"  ‑ Base Score:   {sev.get('baseScore')}\n")
            fh.write(f"  ‑ Base Severity:{sev.get('baseSeverity')}\n")
            fh.write(f"  ‑ Vector:       {sev.get('cvssCode')}\n")
            fh.write("CPEs:\n")
            for c in cve["cpe"]:
                # Adaptado para imprimir os intervalos de versão corretamente
                intervals = c['version_intervals']
                if not intervals:
                    version_str = "no version info"
                else:
                    parts = []
                    for iv in intervals:
                        if iv['label'] == "versions_all":
                            parts.append("all versions")
                        else:
                            parts.append(f"{iv['min']} - {iv['max']}")
                    version_str = "; ".join(parts)
                fh.write(
                    f"  ‑ {c['vendor']} | {c['product']} | {version_str}\n")
            fh.write("References:\n")
            for r in cve["references"]:
                fh.write(f"  ‑ {r.get('url')}\n")
            fh.write("\n" + "‑" * 60 + "\n\n")


if __name__ == "__main__":
    start_date = datetime(2020, 1, 1)
    end_date = datetime(2025, 12, 31)

    cves = fetch_cves_for_package(start_date, end_date)
    print(f"Total CVEs Linux-related fetched: {len(cves)}")

    # write_to_file(cves, "linux_related_cves.txt")
