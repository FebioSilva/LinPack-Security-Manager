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
    description = cve_obj["description"].replace('"', '\\"')
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
        source = ref.get("source", "UnknownSource")
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
        prod_blanks = []
        vendor_blanks = {}
        prod_lines = []

        for cpe in cpes:
            product = cpe.get('product', 'unknown_product')
            version = cpe.get('version', 'unknown')
            vendor_name = cpe.get("vendor", "unknown_vendor")

            prod_key = f"{product}_{version}"
            prod_id = f"cve:prod_{sanitize_for_blank_node(prod_key)}"
            prod_blanks.append(prod_id)

            # Vendor blank node
            if vendor_name not in vendor_blanks:
                vendor_blanks[vendor_name] = f"cve:vendor_{sanitize_for_blank_node(vendor_name)}"
            vendor_id = vendor_blanks[vendor_name]

            prod_lines.append(f"""{prod_id} a cve:Product ;
                cve:product_name "{product}" ;
                cve:product_version "{version}" ;
                cve:product_cpe "cpe:/o:{vendor_name}:{product}:{version}" ;
                cve:has_vendor {vendor_id} .""")

        sparql += f"{', '.join(prod_blanks)} .\n\n"
        sparql += "\n".join(prod_lines)

        vendor_lines = []
        for name, blank in vendor_blanks.items():
            vendor_lines.append(f"""{blank} a cve:Vendor ;
                cve:vendor_name "{name}" .""")

        sparql += "\n\n" + "\n".join(vendor_lines)

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
            {"product": "apache", "version": "2.4", "vendor": "apache_vendor"}
        ]
    }

    print(cve_object_to_sparql(cve_example))
