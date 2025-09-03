import shodan
import sys
import pandas as pd

# --- CONFIGURAÇÃO ---
# IMPORTANTE: Cole sua chave da API do Shodan aqui.
SHODAN_API_KEY = "wLIYt74eSdpXxDSKhOoV31NegkYtihhN"

# Nome do arquivo que contém a lista de IPs
ARQUIVO_IPS = 'ips.txt'

# Nome do arquivo de saída para salvar os resultados
ARQUIVO_SAIDA = 'resultados_shodan.xlsx'

# --- INICIALIZAÇÃO DO SCRIPT ---

# Verifica se a chave da API foi alterada.
if SHODAN_API_KEY == "SUA_CHAVE_DE_API_AQUI":
    print("ERRO: Por favor, insira sua chave da API do Shodan na variável SHODAN_API_KEY.")
    sys.exit(1)

# Inicializa a API do Shodan
try:
    api = shodan.Shodan(SHODAN_API_KEY)
except shodan.APIError as e:
    print(f"Erro ao conectar com a API do Shodan: {e}")
    sys.exit(1)

# --- LEITURA E PROCESSAMENTO DOS IPS ---

try:
    # Abre o arquivo de IPs para leitura
    with open(ARQUIVO_IPS, 'r') as f:
        ips_para_verificar = [linha.strip() for linha in f.readlines()]
    print(f"Encontrados {len(ips_para_verificar)} IPs para análise.")

except FileNotFoundError:
    print(f"ERRO: O arquivo '{ARQUIVO_IPS}' não foi encontrado. Verifique se ele está na mesma pasta que o script.")
    sys.exit(1)

# Cria uma lista vazia para armazenar os resultados de forma estruturada
resultados_finais = []

# Itera sobre cada IP da lista
for ip in ips_para_verificar:
    if not ip:  # Pula linhas em branco
        continue

    print(f"\n[+] Verificando IP: {ip}")

    try:
        # A função api.host() busca todas as informações de um IP.
        host_info = api.host(ip)

        # Itera sobre cada serviço/porta encontrado
        for servico in host_info['data']:
            # Extrai as vulnerabilidades (CVEs), se existirem
            cves = 'N/A'
            if 'vulns' in servico and servico['vulns']:
                cves = ', '.join(servico['vulns'].keys())
            
            # Adiciona uma linha de dados à nossa lista de resultados
            resultados_finais.append({
                'IP': ip,
                'Organização': host_info.get('org', 'N/A'),
                'País': host_info.get('country_name', 'N/A'),
                'Cidade': host_info.get('city', 'N/A'),
                'Porta': servico.get('port', 'N/A'),
                'Transporte': servico.get('transport', 'N/A'),
                'Serviço': servico.get('product', 'N/A'),
                'Vulnerabilidades (CVEs)': cves,
                'Banner': servico.get('data', 'N/A').strip()
            })

    except shodan.APIError as e:
        # Se houver um erro (ex: IP não encontrado, acesso negado), registra na planilha
        error_message = f"Erro na API do Shodan: {e}"
        print(f"  [!] {error_message}")
        resultados_finais.append({
            'IP': ip,
            'Organização': error_message,
            'País': 'N/A',
            'Cidade': 'N/A',
            'Porta': 'N/A',
            'Transporte': 'N/A',
            'Serviço': 'N/A',
            'Vulnerabilidades (CVEs)': 'N/A',
            'Banner': 'N/A'
        })

# --- SALVANDO OS RESULTADOS NO EXCEL ---

if resultados_finais:
    # Converte a lista de resultados em um DataFrame do pandas
    df = pd.DataFrame(resultados_finais)
    
    # Salva o DataFrame em um arquivo Excel
    try:
        df.to_excel(ARQUIVO_SAIDA, index=False, engine='openpyxl')
        print(f"\nAnálise concluída com sucesso! Resultados salvos em '{ARQUIVO_SAIDA}'.")
    except Exception as e:
        print(f"\nERRO ao salvar o arquivo Excel: {e}")
else:
    print("\nNenhum resultado foi gerado para salvar.")