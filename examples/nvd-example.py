import requests
import time

def fetch_cves_for_package(package_name):
    # URL da API da NVD para CVE (versão 2.0)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Parâmetros da consulta
    params = {
        "keywordSearch": package_name,  # Filtrar por palavra-chave (nome do pacote)
        "resultsPerPage": 5  # Quantidade de CVEs retornadas
    }
    
    try:
        # Faz a requisição à API
        response = requests.get(url, params=params)
        response.raise_for_status()  # Verifica se a requisição foi bem-sucedida
        
        # Converte a resposta para JSON
        data = response.json()
        
        # Filtra os CVEs que estão relacionados ao pacote
        cves = data.get('vulnerabilities', [])
        
        # Exibe os CVEs encontrados
        for cve in cves:
            cve_data = cve['cve']
            cve_id = cve_data['id']
            description = cve_data['descriptions'][0]['value']
            
            print(f"\n🔍 CVE ID: {cve_id}")
            print(f"📌 Description: {description}")
            
            # Acessando CPE
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
            time.sleep(1)  # Pequeno delay para evitar bloqueios da API
    
    except requests.exceptions.HTTPError as e:
        print(f"❌ Erro HTTP: {e}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro na requisição: {e}")

if __name__ == "__main__":
    package_name = "linux"  # Nome do pacote que você quer pesquisar
    fetch_cves_for_package(package_name)
