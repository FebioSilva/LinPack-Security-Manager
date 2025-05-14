import re


def sanitize_for_blank_node(value):
    """Sanitize string to create a valid blank node identifier."""
    return re.sub(r'[^a-zA-Z0-9_.]', '_', value.strip().lower())


def cve_object_to_sparql(cve_obj, graph_uri="http://localhost:8890/linpack"):
    sparql_prefix = """
PREFIX : <http://www.semanticweb.org/linpack#>
PREFIX cve: <http://purl.org/cyber/cve#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""

    cve_id = cve_obj["id"]
    description = cve_obj["description"].replace('\\', '\\\\').replace('"', '\\"')
    single_line_description = "\\n".join(line.strip() for line in description.splitlines() if line.strip())
    severity = cve_obj["severity"]
    references = cve_obj["references"]
    cpes = cve_obj["cpe"]

    sparql = sparql_prefix + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
    cve:{cve_id} a cve:CVE ;
                cve:description "{single_line_description}" ;
                cve:base_score {-1 if severity.get("baseScore") == None else severity.get("baseScore", 0)} ;
                cve:base_severity "{severity.get("baseSeverity")}" ;
                cve:cvss_version "{severity.get("cvssVersion")}" ;
                cve:cvss_code "{severity.get("cvssCode")}" ;
"""

    # References
    ref_lines = []
    ref_blanks = []
    for ref in references:
        source = ref.get("source", "unknown_source")
        name = ref.get("tags", [source])[0]
        ref_id = f"cve:ref_{sanitize_for_blank_node(name)}"
        ref_blanks.append(ref_id)
        url = ref.get("url", "")
        ref_lines.append(f"""    {ref_id} a cve:References ;
           cve:url "{url}" ;
           cve:ref_source "{source}" ;
           cve:ref_name "{name}" .""")

    sparql += f"                cve:has_references {', '.join(ref_blanks)} .\n\n"
    sparql += "\n".join(ref_lines)

    # Products and vendors
    if cpes:
        sparql += f"\n\n    cve:{cve_id} cve:has_affected_product "
        prod_blanks = {}
        vendor_blanks = {}
        version_blanks = {}

        prod_lines = []
        for cpe in cpes:
            product = cpe.get('product', 'unknown_product')
            version = cpe.get('version', 'unknown_version')
            first_version = cpe.get('startVersion')
            last_version = cpe.get('endVersion')
            vendor = cpe.get("vendor", "unknown_vendor")

            prod = f"{product}"
            if prod not in prod_blanks:
                prod_blanks[prod] = f"cve:prod_{sanitize_for_blank_node(prod)}"
            prod_id = prod_blanks[prod]

            # Vendor blank node
            if vendor not in vendor_blanks:
                vendor_blanks[vendor] = {"vendor": f"cve:vendor_{sanitize_for_blank_node(vendor)}", "product": prod_id}
            vendor_id = vendor_blanks[vendor]["vendor"]

            # Version blank node
            if "none" not in version_blanks:
                version_blanks["none"] = f"cve:version_none"
            if version != "*":
                if version not in version_blanks:
                    version_blanks[version] = f"cve:version_{sanitize_for_blank_node(version)}"
            else:
                if first_version != None:
                    if first_version not in version_blanks:
                        version_blanks[first_version] = f"cve:version_{sanitize_for_blank_node(first_version)}"
                if last_version != None:
                    if last_version not in version_blanks:
                        version_blanks[last_version] = f"cve:version_{sanitize_for_blank_node(last_version)}"
            first_version_id = version_blanks[version] if version != "*" else (version_blanks[first_version] if first_version != None else version_blanks["none"])
            last_version_id = version_blanks["none"] if version != "*" else (version_blanks[last_version] if last_version != None else version_blanks["none"])

            prod_lines.append(f"""    {prod_id} a cve:Product ;
                cve:product_name "{product}" ;
                cve:has_cve cve:{cve_id} ;
                cve:has_vendor {vendor_id} ;
                cve:has_first_version {first_version_id} ;
                cve:has_last_version {last_version_id} .""")
        
        prod_blanks_aux = []
        for product, blank in prod_blanks.items():
            prod_blanks_aux.append(blank)
        sparql += f"{', '.join(prod_blanks_aux)} .\n\n"
        sparql += "\n".join(prod_lines)

        vendor_lines = []
        for name, blank in vendor_blanks.items():
            vendor_lines.append(f"""    {blank["vendor"]} a cve:Vendor ;
                cve:vendor_name "{name}" ;
                cve:has_product {blank["product"]} .""")

        sparql += "\n\n" + "\n".join(vendor_lines)

        version_lines = []
        for version, blank in version_blanks.items():
            if version != "none":
                version_parts = version.split(".")
                major_part = int(version_parts[0])
                minor_part = int(version_parts[1])
                patch_part = int(version_parts[2]) if len(version_parts) == 3 else 0
                version_lines.append(f"""    {blank} a cve:Version ;
                    cve:version_major {major_part} ;
                    cve:version_minor {minor_part} ;
                    cve:version_patch {patch_part} .""")
            
            else:
                version_lines.append(f"""    {blank} a cve:Version ;
                    cve:version_major 0 ;
                    cve:version_minor 0 ;
                    cve:version_patch 0 .""")

        sparql += "\n\n" + "\n".join(version_lines)    

    sparql += "\n  }\n}"
    return sparql


if __name__ == "__main__":
    # Example CVE object for testing
    cve_example = {
        "id": "CVE-2023-12345",
        "description": "Example vulnerability description.",
        "severity": {
            "baseScore": 7.5,
            "baseSeverity": "HIGH",
            "cvssVersion": "3.1",
            "cvssCode": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "references": [
            {"url": "http://example.com/vuln1",
                "source": "ExampleSource", "tags": ["tag1"]},
            {"url": "http://example.com/vuln2",
                "source": "AnotherSource", "tags": ["tag2"]}
        ],
        "cpe": [
            {"product": "linux", "version": "5.4", "vendor": "linux_vendor"},
            {"product": "apache", "version": "2.4.6", "vendor": "apache_vendor"},
            {"product": "linux", "version": "*", "vendor": "linux_vendor", "startVersion": "5.4", "endVersion": "5.4.8"},
            {"product": "apache", "version": "*", "vendor": "linux_vendor", "endVersion": "2.4"}
        ]
    }

    print(cve_object_to_sparql(cve_example))
