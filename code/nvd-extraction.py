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

            cvss_data = cve_data.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {})
            severity = {
                "cvssVersion": cvss_data.get('version'),
                "baseScore": cvss_data.get('baseScore'),
                "baseSeverity": cve_data.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity'),
                "cvssCode": cvss_data.get('vectorString')
            }
            references = cve_data['references']
            
            # Acessando CPE
            configurations = cve_data.get('configurations', [])
            cpe_list = []
            if configurations:
                for node in configurations[0]['nodes']:
                    for cpe_match in node['cpeMatch']:
                        cpe_parts = cpe_match.get('criteria', '').split(':')
                        cpe_list.append({
                            "part": cpe_parts[1] if len(cpe_parts) > 1 else None,
                            "vendor": cpe_parts[3] if len(cpe_parts) > 3 else None,
                            "product": cpe_parts[4] if len(cpe_parts) > 4 else None,
                            "version": cpe_parts[5] if len(cpe_parts) > 5 else None,
                            "update": cpe_parts[6] if len(cpe_parts) > 6 else None,
                            "edition": cpe_parts[7] if len(cpe_parts) > 7 else None,
                            "language": cpe_parts[8] if len(cpe_parts) > 8 else None,
                            "sw_edition": cpe_parts[9] if len(cpe_parts) > 9 else None,
                            "target_sw": cpe_parts[10] if len(cpe_parts) > 10 else None,
                            "target_hw": cpe_parts[11] if len(cpe_parts) > 11 else None,
                            "other": cpe_parts[12] if len(cpe_parts) > 12 else None
                        })
            
            # Cria o objeto CVE com as propriedades extraídas
            cve_object = {
                "id": cve_id,
                "description": description,
                "severity": severity,
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