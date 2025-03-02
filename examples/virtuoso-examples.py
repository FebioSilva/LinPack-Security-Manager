from SPARQLWrapper import SPARQLWrapper, POST, JSON

# SPARQL endpoint URL (replace with your actual endpoint)
SPARQL_ENDPOINT = "http://localhost:8890/sparql"

# Authentication (if required)
# USERNAME = "your_username"
# PASSWORD = "your_password"

# Initialize SPARQLWrapper
sparql = SPARQLWrapper(SPARQL_ENDPOINT)
# sparql.setCredentials(USERNAME, PASSWORD)

# Add a new class to the ontology
insert_query = """
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX ex: <http://example.org#>

INSERT DATA {
  GRAPH <http://localhost:8890/example> {
    ex:NewClass rdf:type rdfs:Class ;
                rdfs:label "New Class" .
  }
}
"""

sparql.setMethod(POST)
sparql.setQuery(insert_query)
sparql.query()

print("Inserted new class into the ontology.")

# SPARQL query to retrieve all classes
query = """
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT DISTINCT ?class
FROM <http://localhost:8890/example>
WHERE {
  { ?class rdf:type owl:Class . }
  UNION
  { ?class rdf:type rdfs:Class . }
}
"""

# Set the query
sparql.setQuery(query)
sparql.setReturnFormat(JSON)

# Execute the query and get results
response = sparql.query().convert()

# Ensure response is properly parsed into JSON
if isinstance(response, bytes):
    import json
    response = json.loads(response.decode("utf-8"))  # Decode bytes and load JSON

# Print the retrieved classes
print("Classes in the ontology:")
for result in response["results"]["bindings"]:
    print(result["class"]["value"])