import requests

def fetch_cves_for_package(package_name):
    # URL da API da NVD para CVE (versão 2.0)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Parâmetros da consulta
    params = {
        "keywordSearch": package_name,  # Filtrar por palavra-chave (nome do pacote)
        "resultsPerPage": 50  # Quantidade de CVEs retornadas
    }
    
    try:
        # Faz a requisição à API
        response = requests.get(url, params=params)
        response.raise_for_status()  # Verifica se a requisição foi bem-sucedida
        
        # Converte a resposta para JSON
        data = response.json()
        
        # Filtra os CVEs que estão relacionados ao pacote
        cves = data.get('vulnerabilities', [])
        
        # Lista para armazenar os objetos de CVE
        cve_objects = []
        
        # Exibe os CVEs encontrados
        for cve in cves:
            cve_data = cve['cve']
            
            # Extrai as informações
            cve_id = cve_data['id']
            description = cve_data['descriptions'][0]['value']
            cvssVersion = cve_data['metrics']['cvssMetricV2'][0]['cvssData']['version']
            baseScore = cve_data['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
            baseSeverity = cve_data['metrics']['cvssMetricV2'][0]['baseSeverity']
            cvssCode = cve_data['metrics']['cvssMetricV2'][0]['cvssData']['vectorString']
            references = cve_data['references']
            
            # Acessando CPE
            configurations = cve_data.get('configurations', [])
            cpe_list = []
            if configurations:
                for node in configurations[0]['nodes']:
                    for cpe_match in node['cpeMatch']:
                        cpe_list.append(cpe_match['criteria'])
            
            # Cria o objeto CVE com as propriedades extraídas
            cve_object = {
                "id": cve_id,
                "description": description,
                "severity": {
                    "cvssVersion": cvssVersion,
                    "baseScore": baseScore,
                    "baseSeverity": baseSeverity,
                    "cvssCode": cvssCode
                },
                "references": references,
                "cpe": cpe_list
            }
            
            # Adiciona o objeto à lista
            cve_objects.append(cve_object)
        
        # Retorna a lista de objetos CVE
        return cve_objects
    
    except requests.exceptions.HTTPError as e:
        print(f"❌ Erro HTTP: {e}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro na requisição: {e}")

if __name__ == "__main__":
    package_name = "linux"  # Nome do pacote que você quer pesquisar
    cves = fetch_cves_for_package(package_name)
    
    # Exibe os objetos CVE
    for cve in cves:
        print(cve)