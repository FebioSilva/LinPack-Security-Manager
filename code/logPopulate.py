import re


def sanitize_for_uri(value):
    return re.sub(r'[^a-zA-Z0-9]', '_', value)


def generate_package_uri(package_name, *versions):
    parts = [sanitize_for_uri(package_name)] + \
        [sanitize_for_uri(v) for v in versions]
    return "_".join(parts)


def dpkg_log_to_sparql(log_obj, graph_uri="http://localhost:8890/linpack"):
    sparql_prefix = """
PREFIX logs: <http://www.semanticweb.org/logs-ontology-v2#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""

    log_id = f"log{log_obj['log_id']}"
    log_type = log_obj["type"].capitalize() + "Event"

    sparql = sparql_prefix + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
    logs:{log_id} rdf:type logs:{log_type} ;
                    logs:timestamp "{log_obj['timestamp']}"^^xsd:dateTime ;
"""
    if log_obj["type"] == "action":
        version_old = 'none' if log_obj["version_old"] == '<none>' else log_obj["version_old"]
        version_new = 'none' if log_obj["version_new"] == '<none>' else log_obj["version_new"]
        package_uri = generate_package_uri(
            log_obj['package'], version_old, version_new)
        sparql += f"""                    logs:action "{log_obj['action']}" ;
                    logs:has_package logs:{package_uri} ;  
"""
    elif log_obj["type"] == "state":
        package_uri = generate_package_uri(
            log_obj['package'], log_obj['version'])
        sparql += f"""                    logs:state "{log_obj['state']}" ;
                    logs:has_package logs:{package_uri} ;  
"""
    elif log_obj["type"] == "conffile":
        sparql += f"""            logs:filepath "{log_obj['filepath']}" ;      
                        logs:decision "{log_obj['decision']}" ;
"""
    elif log_obj["type"] == "startup":
        sparql += f"""                    logs:context "{log_obj['context']}" ;
                    logs:command "{log_obj['command']}" ;
"""

    sparql = sparql.rstrip(" ;\n") + " .\n"

    if 'package' in log_obj:
        if log_obj["type"] == "action":
            version_old = 'none' if log_obj["version_old"] == '<none>' else log_obj["version_old"]
            version_new = 'none' if log_obj["version_new"] == '<none>' else log_obj["version_new"]
            package_uri = generate_package_uri(
                log_obj['package'], version_old, version_new)
            sparql += f"""
    logs:{package_uri} rdf:type logs:Package ;
                    logs:package_name "{log_obj['package']}" ;
                    logs:package_architeture "{log_obj['architecture']}" ;
                    logs:current_version "{log_obj['version_old']}" ;
                    logs:new_version "{log_obj['version_new']}" .
        """
        elif log_obj["type"] == "state":
            package_uri = generate_package_uri(
                log_obj['package'], log_obj['version'])
            sparql += f"""     
    logs:{package_uri} rdf:type logs:Package ;
                    logs:package_name "{log_obj['package']}" ;
                    logs:package_architecture "{log_obj['architecture']}" ;
                    logs:current_version "{log_obj['version']}" ;
                    logs:new_version "{log_obj['version']}" .
        """

    sparql += """
  }
}
  """
    return sparql
