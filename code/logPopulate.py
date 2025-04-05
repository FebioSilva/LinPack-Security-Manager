def dpkg_log_to_sparql(log_obj, graph_uri="http://localhost:8890/linpack"):
    sparql_prefix = """
PREFIX logs: <http://www.semanticweb.org/logs-ontology-v2#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""

    log_id = f"log{log_obj['log_id']}"
    # ActionLog, StateLog, etc.
    log_type = log_obj["type"].capitalize() + "Log"

    sparql = sparql_prefix + f"""
INSERT DATA {{
  GRAPH <{graph_uri}> {{
    logs:{log_id} rdf:type logs:{log_type} ;
                  logs:hasTimestamp "{log_obj['timestamp']}"^^xsd:dateTime ;
"""

    if log_obj["type"] == "action":
        sparql += f"""                  logs:hasAction "{log_obj['action']}" ;
                  logs:hasPackage "{log_obj['package']}" ;
                  logs:hasArchitecture "{log_obj['architecture']}" ;
                  logs:hasOldVersion "{log_obj['version_old']}" ;
                  logs:hasNewVersion "{log_obj['version_new']}" ;
"""

    elif log_obj["type"] == "state":
        sparql += f"""                  logs:hasState "{log_obj['state']}" ;
                  logs:hasPackage "{log_obj['package']}" ;
                  logs:hasArchitecture "{log_obj['architecture']}" ;
                  logs:hasVersion "{log_obj['version']}" ;
"""

    elif log_obj["type"] == "conffile":
        sparql += f"""                  logs:hasFilePath "{log_obj['filepath']}" ;
                  logs:hasAction "{log_obj['action']}" ;
"""

    elif log_obj["type"] == "startup":
        sparql += f"""                  logs:hasContext "{log_obj['context']}" ;
                  logs:hasAction "{log_obj['action']}" ;
"""

    # Remove o último ponto e vírgula
    sparql = sparql.rstrip(" ;\n") + " .\n  }\n}"
    return sparql
