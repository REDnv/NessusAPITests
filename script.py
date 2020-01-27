import requests, json, urllib3, time, re
#Uso temporário para suprimir o erro do SSLVerify
urllib3.disable_warnings()

# Dados de Acesso.
aKey = "<Nessus_AccessKey>"
sKey = "<Nessus_SecretKey>"
url = "<nessus_basicUrl>"

#Cabeçalho que deve ser enviado para autenticação.
headers = {'X-ApiKeys': 'accessKey=%s; secretKey=%s'%(aKey,sKey)}

#Início de variáveis e arrays.
foldersNessus = []
foldersText = []
foldersScans = []
a=0

#Realiza o request na página do nessus autenticando e desabilitando o SSLVerify.
scansDir = requests.get("%s/scans"%url, headers=headers, verify=False)
#print(scansDir.content)

#Realiza a leitura do conteúdo da página.
comments = json.loads(scansDir.content)

#Realiza a leitura de ID das pastas e as acrecenta na array de Pastas do Nessus.
for n in comments['folders']:
    foldersNessus.append(comments['folders'][a]['id'])
    foldersScans.append(comments['scans'][a]['folder_id'])
    foldersText.append(str(comments['folders'][a]['id']) + " - " + comments['folders'][a]['name'])
    a+=1

print("Qual scan deseja exportar?")
print("ID - Ativo")
#Mostra a lista de Pasta de Ativos do Nessus
for y in foldersText:
    print(y)

#Pede para digitar o ID de alguma pasta de Ativo do Nessus
escolhaScan = int(input('Digite o ID do Ativo: '))

#Encontra o índice do ID da pasta do Ativo escolhido
#E localiza os scans dentro da pasta do Ativo.
indiceScan = foldersScans.index(escolhaScan)
#Printa na tela os scans encontrados na pasta com os devidos ID para export.
idScanIndice = (comments['scans'][indiceScan]['id'])
print(str(idScanIndice) + " - " + comments['scans'][indiceScan]['name'])

#Formatos de Export's.
formatPDF = "pdf"
formatNESSUS = "nessus"
formatCSV = "csv"
formatHTML = "html"
formatDB = "db"

#Teste para escolher o formato de Export Report
print("Gerar relatório\n1 - PDF (Executivo)\n2 - Nessus\n3 - CSV\n4 - HTML\n5 - DB")
formatEscolha = int(input("Escolha o formato de Export (PDF Default):"))
if(formatEscolha == 1):
    formatExport = formatPDF
    payload = {"format":"%s"%formatExport,"chapters":"vuln_hosts_summary","reportContents":{"csvColumns":{},"vulnerabilitySections":{},"hostSections":{},"formattingOptions":{}},"extraFilters":{"host_ids":[],"plugin_ids":[]}}
elif(formatEscolha == 2):
    formatExport = formatNESSUS
    payload = {"format":"%s"%formatExport}
elif(formatEscolha == 3):
    formatExport = formatCSV
    payload = {"format":"%s"%formatExport}
elif(formatEscolha == 4):
    formatExport = formatHTML
    payload = {"format":"%s"%formatExport}
elif(formatEscolha == 5):
    formatExport = formatDB
    payload = {"format":"%s"%formatExport}
else:
    print("Opção inválida. PDF Gerado.")

#Solução para gerar o token e o file_id do arquivo de export.
urlGetData = ("%s/scans/%d/export"%(url,idScanIndice))
scansGetData = requests.post(urlGetData, headers=headers, verify=False, data=payload)
jsonReport = json.loads(scansGetData.content)
reportToken = jsonReport['token']
reportFileID = jsonReport['file']
#print(reportFileID) # For Debug FileID

#Solução para exportar o relatório
urlReportExport = ("%s/scans/%d/export/%d/download"%(url,idScanIndice,reportFileID))
scansReportExport = requests.get(urlReportExport, headers=headers, verify=False)
while(scansReportExport.status_code == 409):
    scansReportExport = requests.get(urlReportExport, headers=headers, verify=False)
    print("Aguarde. Gerando relatório.")
    time.sleep(10)
    if(scansReportExport.status_code == 200):
        contentDisposition = scansReportExport.headers['Content-Disposition']
        contentLength = scansReportExport.headers.get('Content-Length')
        fileName = re.findall("filename=(.+)", contentDisposition)[0]
        fileName = fileName.replace('"', '')
        open('./Reports/%s'%fileName, 'wb').write(scansReportExport.content)
        print('Relatório salvo com sucesso.')
        print('%s - %s bytes'%(fileName,contentLength))
