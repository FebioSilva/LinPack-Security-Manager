from datetime import datetime, timedelta
import nvdExtraction
import dbOperations
import nvdToRDF

if __name__ == "__main__":
    # start_date = datetime(2020, 1, 1)
    start_date = datetime.now() - timedelta(days=119)
    end_date = datetime.now()

    cves = nvdExtraction.fetch_cves_for_package(start_date, end_date)

    print("******************************************")
    print("CVE objects fetched:", len(cves))
    for cve in cves:
        print(cve)
        print("*****************************************")

        # Usa a função otimizada com múltiplos blocos
        sparql_blocks = nvdToRDF.cve_object_to_sparql(cve)

        # Exporta o CVE específico se for o que procuras
        if cve["id"] == "CVE-2025-33138":
            with open("CVE-2025-33138.sparql", "w", encoding="utf-8") as writer:
                writer.write("\n\n".join(sparql_blocks))

        # Insere cada bloco no endpoint Virtuoso
        for sparql_block in sparql_blocks:
            dbOperations.insert_into_graph(sparql_block)

    print("******************************************")
    print("CVE objects inserted into the graph database.")
