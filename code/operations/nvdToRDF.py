import re
from datetime import datetime


def sanitize_for_blank_node(value: str) -> str:
    """Remove caracteres não alfanuméricos para gerar IDs compatíveis com blank nodes."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", value.strip().lower())


def escape_string_for_sparql(value: str) -> str:
    """Escapa aspas e barras invertidas para uso seguro em strings SPARQL."""
    value = re.sub(r'\\(?=["\\])', r'\\\\', value)
    value = re.sub(r'\\(?!["\\])', '', value)
    return value.replace('"', '\\"')


def process_version_interval(version, start_v, end_v, vendor, product, cve_id):
    """
    Gera blocos RDF/SPARQL para intervalos de versões.
    Se version estiver preenchido e diferente de '*', gera versão única.
    Se intervalo (start_v ou end_v) existir, gera intervalo.
    Se nada, cria genérico 'all versions'.
    """
    ver_blocks = []
    if version and version != "*":
        ver_id = f"cve:vers_{sanitize_for_blank_node(version)}"
        ver_block = f"""    {ver_id} a cve:Versions ;
        cve:version "{escape_string_for_sparql(version)}" ;
        cve:has_cve_affecting_product cve:{cve_id} ."""
        ver_blocks.append((ver_id, ver_block))

    elif start_v or end_v:
        min_v = start_v if start_v else "*"
        max_v = end_v if end_v else "*"
        ver_id = f"cve:vers_{sanitize_for_blank_node(min_v)}-{sanitize_for_blank_node(max_v)}"
        ver_block = f"""    {ver_id} a cve:Versions ;
        cve:min "{escape_string_for_sparql(min_v)}" ;
        cve:max "{escape_string_for_sparql(max_v)}" ;
        cve:has_cve_affecting_product cve:{cve_id} ."""
        ver_blocks.append((ver_id, ver_block))

    else:
        # Versão genérica "all versions"
        ver_id = "cve:vers_all"
        ver_block = f"""    {ver_id} a cve:Versions ;
        cve:has_cve_affecting_product cve:{cve_id} ."""
        ver_blocks.append((ver_id, ver_block))

    return ver_blocks


def is_valid_intervals(v_intervals):
    # Verifica se a lista de intervalos tem pelo menos um intervalo com min ou max != None e != '*'
    if not v_intervals:
        return False
    for interval in v_intervals:
        min_v = interval.get("min")
        max_v = interval.get("max")
        if (min_v and min_v != "*") or (max_v and max_v != "*"):
            return True
    return False


def cve_object_to_sparql(cve_obj, graph_uri="http://localhost:8890/linpack"):
    sparql_prefix = """
PREFIX cve: <http://purl.org/cyber/cve#>
PREFIX lin: <http://www.semanticweb.org/linpack/>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""

    cve_id = cve_obj["id"]
    pub_date = cve_obj.get("pubDate")
    if isinstance(pub_date, datetime):
        pub_date = pub_date.isoformat()

    description = escape_string_for_sparql(cve_obj["description"])
    description = "\\n".join(l.strip()
                             for l in description.splitlines() if l.strip())

    sev = cve_obj.get("severity", {})
    refs = cve_obj.get("references", [])
    cpes = cve_obj.get("cpe", [])

    queries = []

    # Monta os predicados do CVE principal
    predicates = [
        f'cve:description "{description}"',
        f'cve:base_score {sev.get("baseScore", -1)}',
        f'cve:base_severity "{escape_string_for_sparql(sev.get("baseSeverity", ""))}"',
        f'cve:cvss_version "{escape_string_for_sparql(sev.get("cvssVersion", ""))}"',
        f'cve:cvss_code "{escape_string_for_sparql(sev.get("cvssCode", ""))}"',
    ]
    if pub_date:
        predicates.append(f'cve:pub_date "{pub_date}"^^xsd:dateTime')

    triples_str = ""
    if predicates:
        triples_str = " ;\n        ".join(predicates[:-1])
        if len(predicates) > 1:
            triples_str += " ;\n        "
        triples_str += predicates[-1] + " ."

    queries.append(
        sparql_prefix + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
    cve:{cve_id} a cve:CVE ;
        {triples_str}
  }}
}}"""
    )

    # Processa referências
    if refs:
        blank_map = {}
        for ref in refs:
            src = escape_string_for_sparql(ref.get("source", "unknown"))
            url = escape_string_for_sparql(ref.get("url", ""))
            name = sanitize_for_blank_node(f"{src}_{url}")
            blank_map[id(ref)] = f"cve:ref_{name}"

        link_triple = f"    cve:{cve_id} cve:has_references " \
            f"{', '.join(blank_map.values())} ."

        triples = []
        for ref in refs:
            bid = blank_map[id(ref)]
            src = escape_string_for_sparql(ref.get("source", "unknown"))
            url = escape_string_for_sparql(ref.get("url", ""))
            triples.append(f"""    {bid} a cve:References ;
        cve:url "{url}" ;
        cve:ref_source "{src}" ;
        cve:ref_name "{src}_{url}" .""")

        queries.append(
            sparql_prefix + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
{link_triple}
{chr(10).join(triples)}
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
        prd_id = f"cve:prod_{sanitize_for_blank_node(vendor + '_' + product)}"

        version_intervals = cpe.get("version_intervals")

        # Extrai da configuração se version_intervals for inválido (vazio, None, ou só None/"*")
        if not is_valid_intervals(version_intervals):
            version_intervals = []
            configurations = cpe.get("configurations", [])
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_matches = node.get("cpeMatch", [])
                    for cpe_match in cpe_matches:
                        ver_start = cpe_match.get("versionStartIncluding") or cpe_match.get(
                            "versionStartExcluding")
                        ver_end = cpe_match.get("versionEndIncluding") or cpe_match.get(
                            "versionEndExcluding")
                        if not ver_start and not ver_end:
                            ver_start = "*"
                            ver_end = "*"
                        version_intervals.append(
                            {"min": ver_start, "max": ver_end, "label": "config_interval"})

        ver_blocks = []
        if version_intervals:
            for interval in version_intervals:
                min_v = interval.get("min")
                max_v = interval.get("max")
                ver_id = f"cve:vers_{sanitize_for_blank_node(min_v or 'none')}-{sanitize_for_blank_node(max_v or 'none')}"

                ver_block = f"""    {ver_id} a cve:Versions ;
            cve:min "{escape_string_for_sparql(min_v or "*")}" ;
            cve:max "{escape_string_for_sparql(max_v or "*")}" ;
            cve:has_cve_affecting_product cve:{cve_id} ."""

                ver_blocks.append((ver_id, ver_block))
        else:
            # fallback para cpe simples com versão direta
            version = cpe.get("version")
            start_v = cpe.get("startVersion")
            end_v = cpe.get("endVersion")

            ver_blocks = process_version_interval(
                version, start_v, end_v, vendor, product, cve_id)

        # Adiciona versões
        for ver_id, ver_block in ver_blocks:
            if ver_id not in version_seen:
                version_seen.add(ver_id)
                version_lines.append(ver_block)

            # Adiciona produto referenciando versão
            if prd_id not in product_seen:
                product_seen.add(prd_id)
                product_lines.append(f"""    {prd_id} a cve:Product ;
            cve:product_name "{escape_string_for_sparql(product)}" ;
            cve:has_vendor {vnd_id} ;
            cve:has_cve cve:{cve_id} ;
            cve:has_version_interval {ver_id} .""")

                # Aqui adiciona a ligação inversa CVE -> Produto
                product_lines.append(
                    f"    cve:{cve_id} cve:has_affected_product {prd_id} .")

        # Adiciona vendor
        if vnd_id not in vendor_seen:
            vendor_seen.add(vnd_id)
            vendor_lines.append(f"""    {vnd_id} a cve:Vendor ;
            cve:vendor_name "{escape_string_for_sparql(vendor)}" ;
            cve:has_owned_product {prd_id} .""")

    def batch_insert(lines):
        for i in range(0, len(lines), 50):
            yield (
                sparql_prefix + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
{chr(10).join(lines[i:i + 50])}
  }}
}}"""
            )

    queries.extend(batch_insert(product_lines))
    queries.extend(batch_insert(vendor_lines))
    queries.extend(batch_insert(version_lines))

    return queries


# ─────────────────────────────
#  CLI de teste rápido
# ─────────────────────────────


if __name__ == "__main__":
    cve = {
        "id": "CVE-2025-33136",
        "description": "IBM Aspera Faspex 5.0.0 through 5.0.12 could allow an authenticated user to obtain sensitive information or perform unauthorized actions on behalf of another user due to improper protection of assumed immutable data.",
        "severity": {
            "cvssVersion": "3.1",
            "baseScore": 7.1,
            "baseSeverity": "HIGH",
            "cvssCode": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        },
        "references": [
            {
                "source": "psirt@us.ibm.com",
                "url": "https://www.ibm.com/support/pages/node/7234114",
                "tags": ["Vendor Advisory"],
            }
        ],
        "cpe": [
            {
                "vendor": "ibm",
                "product": "aspera_faspex",
                "version_intervals": [
                    {"min": None, "max": None, "label": "versions_all"}
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "versionStartIncluding": "5.0.0",
                                        "versionEndIncluding": "5.0.12"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "target_hw": "*",
            }
        ],
        "pubDate": datetime(2025, 5, 22, 17, 15, 23, 420000),
    }

    sparql_queries = cve_object_to_sparql(cve)
    for query in sparql_queries:
        print(query)
        print("\n" + "="*40 + "\n")
