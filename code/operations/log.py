import logExtraction
import logToRDF
import logAuxiliary
import dbOperations

if __name__ == "__main__":
    input_file = "../../resources/dpkg.log"
    parser = logExtraction.LogParser(input_file)
    parser.parse_log()

    for log in parser.parsed_logs:
        print(log)
        print("*****************************************")
        matched_product = None
        if log["type"] == "action":
            ask_for_package_query = logAuxiliary.ask_for_package_to_sparql(log)
            pkg_exists = dbOperations.ask_for_package(ask_for_package_query)["boolean"]
            if pkg_exists and (log["action"] == "install" or log["action"] == "remove" or log["action"] == "upgrade" or log["action"] == "trigproc" or log["action"] == "purge"):
                delete_package_query = logAuxiliary.delete_package_to_sparql(log)
                dbOperations.delete_package(delete_package_query)
            matched_product_query = logAuxiliary.get_matched_prods_to_sparql(log["package"])
            matched_products = dbOperations.get_matched_prods(matched_product_query)
            matched_product = logAuxiliary.get_best_matched_prod(log["package"], matched_products)
        log_in_sparql = logToRDF.dpkg_log_to_sparql(log, matched_product)
        print(log_in_sparql)
        #dbOperations.insert_into_graph(log_in_sparql)
        print("-----------------------------------------------")
        print("Insertion completed.")
        print("*****************************************")
