import nvdPopulate
import nvdExtraction
import dbOperations

if __name__ == "__main__":
    cves = nvdExtraction.fetch_cves_for_package("linux")

    for cve in cves:
        print(cve)
        print("*****************************************")
        cve_in_sparql = nvdPopulate.cve_object_to_sparql(cve)
        print(cve_in_sparql)
        # dbOperations.insert_into_graph(cve_in_sparql)
        print("-----------------------------------------------")
