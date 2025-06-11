import re


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
