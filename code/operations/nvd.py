from datetime import datetime
import nvdExtraction
import dbOperations
import nvdToRDF

if __name__ == "__main__":
    start_date = datetime(2020, 1, 1)
    end_date = datetime.now()

    cves = nvdExtraction.fetch_cves_for_package(start_date, end_date)

    print("******************************************")
    print("CVE objects fetched:", len(cves))
    for cve in cves:
        print(cve)
        print("*****************************************")
        cve_in_sparql = nvdToRDF.cve_object_to_sparql(cve)
        # print(cve_in_sparql)
        #dbOperations.insert_into_graph(cve_in_sparql)
        # print("-----------------------------------------------")
    print("******************************************")
    print("CVE objects inserted into the graph database.")
