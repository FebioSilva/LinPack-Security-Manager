from SPARQLWrapper import SPARQLWrapper, POST, JSON

# SPARQL endpoint URL (replace with your actual endpoint)
SPARQL_ENDPOINT = "http://localhost:8890/sparql"

# Authentication (if required)
# USERNAME = "your_username"
# PASSWORD = "your_password"

# Initialize SPARQLWrapper
sparql = SPARQLWrapper(SPARQL_ENDPOINT)
# sparql.setCredentials(USERNAME, PASSWORD)

def ask_for_package(query):
    sparql.setMethod(POST)
    sparql.setReturnFormat(JSON)
    sparql.setQuery(query)
    result = sparql.query().convert()
    return result

def insert_into_graph(query):
    sparql.setMethod(POST)
    sparql.setQuery(query)
    sparql.query()

def delete_package(query):
    sparql.setMethod(POST)
    sparql.setQuery(query)
    sparql.query()