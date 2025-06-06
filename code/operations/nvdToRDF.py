import re


def sanitize_for_blank_node(value: str) -> str:
    # Substitui qualquer caractere que não seja alfanumérico ou underscore por "_"
    return re.sub(r'[^a-zA-Z0-9_]', '_', value.strip().lower())


def escape_string_for_sparql(value: str) -> str:
    # Escapa barras invertidas apenas quando necessário
    value = re.sub(r'\\(?=["\\])', r'\\\\', value)
    value = re.sub(r'\\(?!["\\])', '', value)
    return value.replace('"', '\\"')


def parse_version(version_str: str):
    if not version_str or version_str in {"*", "-", "none"}:
        return 0, 0, 0
    parts = version_str.split(".")[:3]
    nums = []
    for p in parts:
        m = re.match(r"\d+", p)
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)


def cve_object_to_sparql(cve_obj, graph_uri="http://localhost:8890/linpack"):
    sparql_prefix = """
PREFIX : <http://www.semanticweb.org/linpack#>
PREFIX cve: <http://purl.org/cyber/cve#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""
    cve_id = cve_obj["id"]
    description = escape_string_for_sparql(cve_obj["description"])
    single_line_description = "\\n".join(
        escape_string_for_sparql(line.strip())
        for line in description.splitlines()
        if line.strip()
    )
    severity = cve_obj["severity"]
    references = cve_obj["references"]
    cpes = cve_obj["cpe"]

    queries = []

    # ───────────────────────────────── Bloco 1 – nó principal ─────────────────────────────────
    queries.append(
        sparql_prefix + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
    cve:{cve_id} a cve:CVE ;
        cve:description "{single_line_description}" ;
        cve:base_score {-1 if severity.get("baseScore") is None else severity.get("baseScore", 0)} ;
        cve:base_severity "{escape_string_for_sparql(severity.get("baseSeverity", ""))}" ;
        cve:cvss_version "{escape_string_for_sparql(severity.get("cvssVersion", ""))}" ;
        cve:cvss_code "{escape_string_for_sparql(severity.get("cvssCode", ""))}" .
  }}
}}"""
    )

    # ───────────────────────────────── Bloco 2 – referências ─────────────────────────────────
    # ───────────────────────────────── Bloco 2 – referências ─────────────────────────────────
    if references:
        ref_blanks = {}

        # Criar identificadores únicos e seguros
        for ref in references:
            source = escape_string_for_sparql(
                ref.get("source", "unknown_source"))
            url = escape_string_for_sparql(ref.get("url", ""))
            name = f"{source}_{url}"
            sanitized_name = sanitize_for_blank_node(name)
            ref_blanks[name] = f"cve:ref_{sanitized_name}"

        # Linha de ligação com ponto final
        link_line = f"""    cve:{cve_id} cve:has_references {', '.join(ref_blanks.values())} ."""

        # Construção das triplas de cada referência
        ref_lines = []
        for name, ref_id in ref_blanks.items():
            source, _, url_part = name.partition("_")
            source = escape_string_for_sparql(source)
            url = escape_string_for_sparql(url_part)
            full_name = escape_string_for_sparql(name)
            ref_lines.append(f"""    {ref_id} a cve:References ;
            cve:url "{url}" ;
            cve:ref_source "{source}" ;
            cve:ref_name "{full_name}" .""")

        sparql = sparql_prefix + f"""
    INSERT DATA {{
    GRAPH <{graph_uri}> {{
    {link_line}
    {chr(10).join(ref_lines)}
    }}
    }}"""

        queries.append(sparql)

    # ──────────────────────── Blocos 3+ – produtos / vendors / versões ───────────────────────
    prod_blanks, vendor_blanks, version_blanks = {}, {}, {}
    prod_lines, vendor_lines, version_lines = [], [], []

    for cpe in cpes:
        product = cpe.get("product", "unknown_product")
        version = cpe.get("version", "unknown_version")
        first_version = cpe.get("startVersion")
        last_version = cpe.get("endVersion")
        vendor = cpe.get("vendor", "unknown_vendor")

        version_key = version if version not in {
            "*", "-"} else (first_version or "none")
        prod_key = f"{product}_{version_key}"
        prod_id = prod_blanks.setdefault(
            prod_key, f"cve:prod_{sanitize_for_blank_node(prod_key)}"
        )

        vendor_blanks.setdefault(
            vendor,
            {
                "vendor": f"cve:vendor_{sanitize_for_blank_node(vendor)}",
                "product": prod_id,
            },
        )
        vendor_id = vendor_blanks[vendor]["vendor"]

        # blank nodes de versões
        version_blanks.setdefault("none", "cve:version_none")
        if version not in {"*", "-"}:
            version_blanks.setdefault(
                version, f"cve:version_{sanitize_for_blank_node(version)}"
            )
        else:
            if first_version is not None:
                version_blanks.setdefault(
                    first_version,
                    f"cve:version_{sanitize_for_blank_node(first_version)}",
                )
            if last_version is not None:
                version_blanks.setdefault(
                    last_version,
                    f"cve:version_{sanitize_for_blank_node(last_version)}",
                )

        first_version_id = (
            version_blanks.get(version)
            if version not in {"*", "-"}
            else version_blanks.get(first_version, version_blanks["none"])
        )
        last_version_id = (
            version_blanks["none"]
            if version not in {"*", "-"}
            else version_blanks.get(last_version, version_blanks["none"])
        )

        prod_lines.append(
            f"""    {prod_id} a cve:Product ;
        cve:product_name "{escape_string_for_sparql(product)}" ;
        cve:has_cve cve:{cve_id} ;
        cve:has_vendor {vendor_id} ;
        cve:has_first_version {first_version_id} ;
        cve:has_last_version {last_version_id} ."""
        )

    # vendors
    for name, blank in vendor_blanks.items():
        vendor_lines.append(
            f"""    {blank['vendor']} a cve:Vendor ;
        cve:vendor_name "{escape_string_for_sparql(name)}" ;
        cve:has_product {blank['product']} ."""
        )

    # versions
    for version, blank in version_blanks.items():
        major, minor, patch = parse_version(version)
        version_lines.append(
            f"""    {blank} a cve:Version ;
        cve:version_major {major} ;
        cve:version_minor {minor} ;
        cve:version_patch {patch} ;
        cve:has_cve_affecting_product cve:{cve_id} ."""
        )

    # helper p/ dividir blocos
    def make_block(lines):
        return (
            sparql_prefix
            + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
{chr(10).join(lines)}
  }}
}}"""
        )

    for group in (prod_lines, vendor_lines, version_lines):
        for i in range(0, len(group), 50):  # blocos de 50
            queries.append(make_block(group[i: i + 50]))

    return queries


# ─────────────────────────────── teste rápido ────────────────────────────────
if __name__ == "__main__":
    cve = {
        "id": "CVE-2023-12345",
        "description": "This is a test CVE description.",
        "severity": {
            "baseScore": 7.5,
            "baseSeverity": "HIGH",
            "cvssVersion": "3.1",
            "cvssCode": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "references": [
            {
                "source": "NVD",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
            }
        ],
        "cpe": [
            {
                "vendor": "example_vendor",
                "product": "example_product",
                "version": "*",
                "startVersion": None,
                "endVersion": None,
            },
            {
                "vendor": "another_vendor",
                "product": "another_product",
                "version": "1.0.0",
                "startVersion": None,
                "endVersion": None,
            },
        ],
    }

    for i, block in enumerate(cve_object_to_sparql(cve), 1):
        print(f"\n--- SPARQL BLOCK {i} ---\n{block}")
