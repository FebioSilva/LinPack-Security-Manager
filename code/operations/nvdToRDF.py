import re
from datetime import datetime


def sanitize_for_blank_node(value: str) -> str:
    """Sanitize string to create valid blank node IDs (alphanumeric and underscore)."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", (value or "").strip().lower())


def escape_string_for_sparql(value: str) -> str:
    """Escape backslashes, double quotes, and newlines for SPARQL literals."""
    if not value:
        return ""
    value = value.replace("\\", "\\\\")
    value = value.replace('"', '\\"')
    value = value.replace("\n", "\\n")
    value = value.replace("\r", "")
    return value


def normalize_part(v: str | None) -> str:
    """Normalize version parts, converting None or '*' to 'all'."""
    if v in (None, "*"):
        return "all"
    return sanitize_for_blank_node(v)


def process_version_interval(start_v, end_v, cve_id, prd_id):
    """Generate SPARQL triples for version intervals."""
    ver_blocks = []

    if start_v or end_v:
        min_v = start_v if start_v else "*"
        max_v = end_v if end_v else "*"
        ver_id = f"cve:vers_{normalize_part(min_v)}-{normalize_part(max_v)}"
        ver_block = f"""    {ver_id} a cve:Versions ;
        cve:min "{escape_string_for_sparql(min_v)}" ;
        cve:max "{escape_string_for_sparql(max_v)}" ;
        cve:has_product {prd_id} ;
        cve:has_cve_affecting_product cve:{cve_id} ."""
        ver_blocks.append((ver_id, ver_block))
        return ver_blocks

    # Caso todos os versions (sem limites)
    ver_id = "cve:vers_all"
    ver_block = f"""    {ver_id} a cve:Versions ;
        cve:has_product {prd_id} ;
        cve:has_cve_affecting_product cve:{cve_id} ."""
    ver_blocks.append((ver_id, ver_block))
    return ver_blocks




def cve_object_to_sparql(cve_obj, graph_uri="http://localhost:8890/linpack"):
    PREFIX = """
PREFIX cve: <http://purl.org/cyber/cve#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""
    cve_id = cve_obj["id"]
    pub_dt = cve_obj.get("pubDate")
    if isinstance(pub_dt, datetime):
        pub_dt = pub_dt.isoformat()

    desc = escape_string_for_sparql(cve_obj["description"])
    desc = "\\n".join(line.strip()
                      for line in desc.split("\\n") if line.strip())

    sev = cve_obj.get("severity", {})
    refs = cve_obj.get("references", [])
    cpes = cve_obj.get("cpe", [])

    queries = []

    # Main CVE block
    preds = [
        f'cve:description "{desc}"',
        f'cve:base_score {sev.get("baseScore", -1)}',
        f'cve:base_severity "{sev.get("baseSeverity", "")}"',
        f'cve:cvss_version "{sev.get("cvssVersion", "")}"',
        f'cve:cvss_code "{sev.get("cvssCode", "")}"',
    ]
    if pub_dt:
        preds.append(f'cve:pub_date "{pub_dt}"^^xsd:dateTime')

    joiner = ' ;\n        '
    queries.append(
        PREFIX + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
    cve:{cve_id} a cve:CVE ;
        {joiner.join(preds)} .
  }}
}}"""
    )

    # References
    if refs:
        blank_map = {}
        triples_ref = []
        for ref in refs:
            src = escape_string_for_sparql(ref.get("source", "unknown"))
            url = escape_string_for_sparql(ref.get("url", ""))
            bid = f"cve:ref_{sanitize_for_blank_node(src + '_' + url)}"
            blank_map[id(ref)] = bid
            triples_ref.append(f"""    {bid} a cve:References ;
        cve:url "{url}" ;
        cve:ref_source "{src}" ;
        cve:ref_name "{src}_{url}" .""")

        queries.append(
            PREFIX + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
    cve:{cve_id} cve:has_references {', '.join(blank_map.values())} .
{chr(10).join(triples_ref)}
  }}
}}"""
        )

    vendor_seen = set()
    product_seen = set()
    version_seen = set()

    vendor_lines, product_lines, version_lines = [], [], []

    for cpe in cpes:
        vendor = cpe.get("vendor", "unknown_vendor")
        product = cpe.get("product", "unknown_product")
        vnd_id = f"cve:vendor_{sanitize_for_blank_node(vendor)}"
        prd_id = f"cve:prod_{sanitize_for_blank_node(product)}"

        vers_intv = cpe.get("version_intervals", [])
        if not vers_intv:
            vers_intv = [
                {"min": cpe.get("startVersion"), "max": cpe.get("endVersion")}]

        ver_blocks = []
        for iv in vers_intv:
            ver_blocks.extend(
                process_version_interval(iv.get("min"), iv.get("max"), cve_id, prd_id)
            )


        for ver_id, ver_block in ver_blocks:
            if ver_id not in version_seen:
                version_seen.add(ver_id)
                version_lines.append(ver_block)
            product_lines.append(
                f"    {prd_id} cve:has_version_interval {ver_id} .")

        if prd_id not in product_seen:
            product_seen.add(prd_id)
            product_lines.append(f"""    {prd_id} a cve:Product ;
        cve:product_name "{escape_string_for_sparql(product)}" ;
        cve:has_vendor {vnd_id} .""")

        product_lines.append(
            f"    cve:{cve_id} cve:has_affected_product {prd_id} .")

        if vnd_id not in vendor_seen:
            vendor_seen.add(vnd_id)
            vendor_lines.append(f"""    {vnd_id} a cve:Vendor ;
        cve:vendor_name "{escape_string_for_sparql(vendor)}" ;
        cve:has_owned_product {prd_id} .""")

    def batch_insert(lines, chunk=50):
        for i in range(0, len(lines), chunk):
            yield PREFIX + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
{chr(10).join(lines[i:i+chunk])}
  }}
}}"""

    queries.extend(batch_insert(product_lines))
    queries.extend(batch_insert(vendor_lines))
    queries.extend(batch_insert(version_lines))

    return queries


if __name__ == "__main__":
    # Example usage
    cve_example = {
        "id": "CVE-2023-12345",
        "pubDate": datetime(2023, 10, 1, 12, 0),
        "description": "This is a test CVE description.\nIt has multiple lines.",
        "severity": {
            "baseScore": 7.5,
            "baseSeverity": "HIGH",
            "cvssVersion": "3.1",
            "cvssCode": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "references": [
            {"source": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"}
        ],
        "cpe": [
            {
                "vendor": "example_vendor",
                "product": "example-product",
                "version_intervals": [
                    {"min": "1.0", "max": "2.0"}
                ]
            }
        ]
    }

    queries = cve_object_to_sparql(cve_example)
    for query in queries:
        print(query)
