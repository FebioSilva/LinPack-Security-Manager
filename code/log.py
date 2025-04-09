import logExtraction
import logPopulate
import dbOperations

if __name__ == "__main__":
    input_file = "../resources/dpkg.log"
    parser = logExtraction.LogParser(input_file)
    parser.parse_log()

    for log in parser.parsed_logs:
        print(log)
        print("*****************************************")
        log_in_sparql = logPopulate.dpkg_log_to_sparql(log)
        print(log_in_sparql)
        dbOperations.insert_into_graph(log_in_sparql)
        print("-----------------------------------------------")
