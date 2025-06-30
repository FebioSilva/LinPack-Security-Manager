import re
import Levenshtein


def sanitize_for_uri(value):
    if value is None:
        return "none"
    return re.sub(r'[^a-zA-Z0-9]', '_', value)


def generate_package_uri(package_name, *versions):
    parts = [sanitize_for_uri(package_name)] + \
        [sanitize_for_uri(v) for v in versions]
    return "_".join(parts)


def ask_for_package_to_sparql(log_obj, graph_uri="http://localhost:8890/linpack"):
    sparql_prefix = """
PREFIX logs: <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""
    version = log_obj["replace"] if log_obj["action"] == "upgrade" else log_obj["version"]
    package_uri = generate_package_uri(log_obj['package'], version)

    sparql = sparql_prefix + f"""
ASK {{
    GRAPH <{graph_uri}> {{
        logs:{package_uri} a logs:Package .
    }}
}}
"""
    return sparql


def delete_package_to_sparql(log_obj, graph_uri="http://localhost:8890/linpack"):
    sparql_prefix = """
PREFIX logs: <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""

    version = log_obj["replace"] if log_obj["action"] == "upgrade" else log_obj["version"]
    package_uri = generate_package_uri(log_obj['package'], version)

    sparql = sparql_prefix + f"""
DELETE WHERE {{
  GRAPH <{graph_uri}> {{
    logs:{package_uri} ?p ?o .
  }}
}}
"""
    return sparql

def get_matched_prods_to_sparql(package):
    sparql_prefix = """
PREFIX logs: <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX cve:  <http://purl.org/cyber/cve#>
"""

    sparql = sparql_prefix + f"""
SELECT DISTINCT ?product ?product_name
WHERE {{

  ?product a cve:Product ;
           cve:product_name ?product_name .

  FILTER(CONTAINS(LCASE(STR("{sanitize_for_uri(package)}")), LCASE(STR(?product_name))))
}}
"""

    return sparql

def get_best_matched_prod(package, results):
    best_match = None
    best_ratio = 0.0
    for result in results["results"]["bindings"]:
        prod_name = result["product_name"]["value"]
        # Products with one or two letters can make the contains filter not work as intended
        if len(prod_name) >= 3:
            ratio = Levenshtein.ratio(package.lower(), prod_name.lower())
            if ratio > best_ratio:
                best_ratio = ratio
                best_match = prod_name
        else:
            if package == prod_name:
                best_match = prod_name
    return best_match