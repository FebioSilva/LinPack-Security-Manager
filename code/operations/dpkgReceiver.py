from time import sleep
import log

# Reads the file with the new synthetic logs in time intervals of 5 minutes
if __name__ == "__main__":
    while(True):
        print("Generating synthetic dpkg logs...")
        log.process_dpkg_log("../../resources/dpkg_synthetic.log")
        # Delete file if it exists
        with open("../../resources/dpkg_synthetic.log", "w") as f:
            f.write("")
        print("Processing completed.")
        sleep(300) # 5 minutes

           