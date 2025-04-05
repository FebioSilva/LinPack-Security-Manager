def cve_object_to_sparql(cve_obj, graph_uri="http://localhost:8890/linpack"):
    sparql_prefix = """
PREFIX : <http://www.semanticweb.org/linpack/>
PREFIX cve: <http://purl.org/cyber/cve#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""

    cve_id = cve_obj["id"]
    description = cve_obj["description"].replace('"', '\\"')  # escapa aspas
    severity = cve_obj["severity"]
    references = cve_obj["references"]
    cpes = cve_obj["cpe"]

    # Base do INSERT
    sparql = sparql_prefix + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
    cve:{cve_id} a cve:CVE ;
                cve:description "{description}" ;
                cve:base_score {severity.get("baseScore", 0)} ;
                cve:base_severity "{severity.get("baseSeverity", "UNKNOWN")}" ;
                cve:cvss_version "{severity.get("cvssVersion", "2.0")}" ;
                cve:cvss_code "{severity.get("cvssCode", "")}" ;
"""
    # Adiciona as referências
    ref_lines = []
    ref_blanks = []
    for idx, ref in enumerate(references):
        ref_id = f"_:ref{idx+1}"
        ref_blanks.append(ref_id)
        url = ref.get("url", "")
        source = ref.get("source", "UnknownSource")
        name = ref.get("tags", [source])[0]
        ref_lines.append(f"""    {ref_id} a cve:References ;
           cve:url "{url}" ;
           cve:ref_source "{source}" ;
           cve:ref_name "{name}" .""")

    sparql += f"                cve:has_references {', '.join(ref_blanks)} .\n\n"
    sparql += "\n".join(ref_lines)

    # Adiciona produtos
    sparql += f"\n\n    cve:{cve_id} cve:has_affected_product "
    prod_blanks = []
    vendor_blanks = {}
    prod_lines = []
    for idx, cpe in enumerate(cpes):
        prod_id = f"_:prod{idx+1}"
        vendor_name = cpe.get("vendor", "unknown_vendor")
        if vendor_name not in vendor_blanks:
            vendor_blanks[vendor_name] = f"_:vendor{len(vendor_blanks)+1}"
        vendor_id = vendor_blanks[vendor_name]

        prod_blanks.append(prod_id)
        prod_lines.append(f"""{prod_id} a cve:Product ;
            cve:product_name "{cpe.get('product', 'unknown_product')}" ;
            cve:product_version "{cpe.get('version', 'unknown')}" ;
            cve:product_cpe "cpe:/o:{vendor_name}:{cpe.get('product', '')}:{cpe.get('version', '')}" ;
            cve:has_vendor {vendor_id} .""")

    sparql += f"{', '.join(prod_blanks)} .\n\n"
    sparql += "\n".join(prod_lines)

    # Adiciona vendors
    vendor_lines = []
    for name, blank in vendor_blanks.items():
        vendor_lines.append(f"""{blank} a cve:Vendor ;
            cve:vendor_name "{name}" .""")

    sparql += "\n\n" + "\n".join(vendor_lines)
    sparql += "\n  }\n}"
    return sparql
