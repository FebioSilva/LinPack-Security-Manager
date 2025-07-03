from time import sleep
import dpkgGenerator
import log

if __name__ == "__main__":
    # while(True):
        print("Generating synthetic dpkg logs...")
        log.process_dpkg_log("dpkg_synthetic.log")
        # delete file if it exists
        with open("dpkg_synthetic.log", "w") as f:
            f.write("")
        print("Processing completed.")
        # sleep(300) # 5 minutes

           