import re


def sanitize_for_uri(value):
    if value is None:
        return "none"
    return re.sub(r'[^a-zA-Z0-9]', '_', value)


def generate_package_uri(package_name, *versions):
    parts = [sanitize_for_uri(package_name)] + \
        [sanitize_for_uri(v) for v in versions]
    return "_".join(parts)


def dpkg_log_to_sparql(log_obj, graph_uri="http://localhost:8890/linpack"):
    sparql_prefix = """
PREFIX linpack: <http://www.semanticweb.org/linpack/>
PREFIX logs: <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX cve: <http://purl.org/cyber/cve#>
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
        package_uri = generate_package_uri(
            log_obj['package'], log_obj['version'])
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
            package_uri = generate_package_uri(
                log_obj['package'], log_obj['version'])

            if log_obj["action"] == "install" or log_obj["action"] == "trigproc":
                sparql += f"""
        logs:{package_uri} rdf:type logs:Package ;
                        logs:package_name "{sanitize_for_uri(log_obj['package'])}" ;
                        logs:package_architecture "{log_obj['architecture']}" ;
                        logs:version "{log_obj['version']}" ;
                        logs:installed True ;
                        linpack:has_related_product cve:prod_{sanitize_for_uri(log_obj['package'])} .
            """

            elif log_obj["action"] == "remove" or log_obj["action"] == "purge":
                sparql += f"""
        logs:{package_uri} rdf:type logs:Package ;
                        logs:package_name "{sanitize_for_uri(log_obj['package'])}" ;
                        logs:package_architecture "{log_obj['architecture']}" ;
                        logs:version "{log_obj['version']}" ;
                        logs:installed False .
            """

            elif log_obj["action"] == "upgrade":
                old_package_uri = generate_package_uri(
                    log_obj['package'], log_obj['replace'])
                sparql += f"""
        logs:{old_package_uri} rdf:type logs:Package ;
                        logs:package_name "{sanitize_for_uri(log_obj['package'])}" ;
                        logs:package_architecture "{log_obj['architecture']}" ;
                        logs:version "{log_obj['replace']}" ;
                        logs:installed False ;
                        logs:replaced_by logs:{package_uri} .
            """
                sparql += f"""
        logs:{package_uri} rdf:type logs:Package ;
                        logs:package_name "{sanitize_for_uri(log_obj['package'])}" ;
                        logs:package_architecture "{log_obj['architecture']}" ;
                        logs:version "{log_obj['version']}" ;
                        logs:installed True .
            """

    sparql += """
  }
}
  """
    return sparql


if __name__ == "__main__":
    # Example log object
    log_obj = {
        'log_id': 1,
        'type': 'action',
        'timestamp': '2024-02-15 12:34:56',
        'action': 'install',
        'package': 'openssl',
        'architecture': 'amd64',
        'version_old': '1.1.1f-1ubuntu2.16',
        'version_new': '1.1.1f-1ubuntu2.17'
    }
    log_state_obj = {
        'log_id': 2,
        'type': 'state',
        'timestamp': '2024-02-15 12:35:00',
        'state': 'installed',
        'package': 'openssl',
        'architecture': 'amd64',
        'version': '1.1.1f-1ubuntu2.17'
    }

    sparql = dpkg_log_to_sparql(log_obj)
    print(sparql)

    sparql = dpkg_log_to_sparql(log_state_obj)
    print(sparql)
