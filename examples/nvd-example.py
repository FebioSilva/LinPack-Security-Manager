import requests
import time

def fetch_cves_for_package(package_name):
    # NVD API URL for CVE (version 2.0)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Search parameters
    params = {
        "keywordSearch": package_name,  # Filter by keyword (package name)
        "resultsPerPage": 5  # Number of returned CVE's
    }
    
    try:
        # Make the request to the API
        response = requests.get(url, params=params)
        response.raise_for_status()  # Verifica se a requisição foi bem-sucedida
        
        # Convert response to JSON
        data = response.json()
        
        # Filter CVE's related to the searched package
        cves = data.get('vulnerabilities', [])
        
        # Show found CVE's
        for cve in cves:
            cve_data = cve['cve']
            cve_id = cve_data['id']
            description = cve_data['descriptions'][0]['value']
            
            print(f"\n🔍 CVE ID: {cve_id}")
            print(f"📌 Description: {description}")
            
            # Acessing CPE
            configurations = cve_data.get('configurations', [])
            if configurations:
                print("🛠️ CPE Information:")
                for node in configurations[0]['nodes']:
                    for cpe_match in node['cpeMatch']:
                        cpe = cpe_match['criteria']
                        print(f" - {cpe}")
            else:
                print("❌ No CPE information available")
            
            print("-" * 60)
            #time.sleep(1)  # Small delay to avoid being blocked from the API
    
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error: {e}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error on request: {e}")

if __name__ == "__main__":
    package_name = "linux"  # Name of the package that we wish to search for
    fetch_cves_for_package(package_name)
