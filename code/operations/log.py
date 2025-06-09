import logExtraction
import logToRDF
import logAuxiliary
import dbOperations

if __name__ == "__main__":
    input_file = "../resources/dpkg.log"
    parser = logExtraction.LogParser(input_file)
    parser.parse_log()

    for log in parser.parsed_logs:
        print(log)
        print("*****************************************")
        if log["type"] == "action":
            ask_for_package_query = logAuxiliary.ask_for_package_to_sparql(log)
            pkg_exists = dbOperations.ask_for_package(ask_for_package_query)["boolean"]
            if pkg_exists and log["action"] == "install" and log["action"] == "remove" and log["action"] == "upgrade" and log["action"] == "trigproc" and log["action"] == "purge":
                delete_package_query = logAuxiliary.delete_package_to_sparql(log)
                dbOperations.delete_package(delete_package_query)
        log_in_sparql = logToRDF.dpkg_log_to_sparql(log)
        print(log_in_sparql)
        dbOperations.insert_into_graph(log_in_sparql)
        #input()
        print("-----------------------------------------------")
        print("Insertion completed.")
        print("*****************************************")
