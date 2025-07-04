from SPARQLWrapper import SPARQLWrapper, GET, POST, JSON

# SPARQL endpoint URL (replace with your actual endpoint)
SPARQL_ENDPOINT = "http://localhost:8890/sparql"

# Authentication (if required)
# USERNAME = "your_username"
# PASSWORD = "your_password"

# Initialize SPARQLWrapper
sparql = SPARQLWrapper(SPARQL_ENDPOINT)
# sparql.setCredentials(USERNAME, PASSWORD)

# Executes query to ask if a certain package exists in the database
def ask_for_package(query):
    sparql.setMethod(POST)
    sparql.setReturnFormat(JSON)
    sparql.setQuery(query)
    result = sparql.query().convert()
    return result

# Executes query to insert data into the database (Logs or CVEs)
def insert_into_graph(query):
    sparql.setMethod(POST)
    sparql.setQuery(query)
    sparql.query()

# Executes query to delete a certain package that exists in the database
def delete_package(query):
    sparql.setMethod(POST)
    sparql.setQuery(query)
    sparql.query()

# Executes query to get all products whose names are contained within a certain package name
def get_matched_prods(query):
    sparql.setMethod(GET)
    sparql.setReturnFormat(JSON)
    sparql.setQuery(query)
    result = sparql.query().convert()
    return result