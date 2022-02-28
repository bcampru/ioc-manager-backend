import requests
import json
import ipaddress
from app.src import converter

def virustotal(input):
    dic = {'SHA256': "files/",'MD5': "files/", 'URL': "urls/", 'Domain': "domains/", "ipv4": "ip_addresses"}

    variable = dic[input[0]]

    url = 'https://www.virustotal.com/api/v3/' + variable + str(input[1])
    headeris = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        'x-apikey': '8efcd2ce48b4139ff2033d8e6c17de92cca24661ea4236e7b1feda524b01b0d6'
    }

    r = requests.get(url, headers=headeris).json()

    cambio = converter.Converter(variable)

    try:
        dict_web = r['data']['attributes']['last_analysis_results']

        max_detect = 0
        score = 0
        tipo = []
        herramientas = []
        
        for i in dict_web:
            max_detect += 1
            if dict_web[i]["category"] == "malicious" or dict_web[i]["category"] == "suspicious":
                tipo.append(dict_web[i]["result"])
                herramientas.append(dict_web[i]["engine_name"])
                score += 1
            
        res = []    
        for i in tipo:
            if i not in res:
                res.append(i)
        
        tipo = res

        overall = score / max_detect

        if(overall>0.75):
            severity = "critical"
        else:
            if(overall>0.30):
                severity = "high"
            else:
                if(overall>0):
                    severity = "medium"
                else:
                    severity = "none"

        name = input[1].lower()
        if(variable == "files/"):
            try:
                name = r['data']['attributes']['type_description']
            except:
                print("error getting Name File")

        diccionario = {
            "type": input[0].lower(),
            "value": input[1].lower(),
            "score" : str(score),
            "total" : str(max_detect),
            "mark" : tipo[1:-1],
            "antiVir" : str(herramientas)[1:-1].lower(),
            "overall" : overall,
            "severity" : severity,
            "description" : str(input[2]),
            "source" : str(input[3]),
            "name": name,
            "expiration": cambio.converter()
        }

    except:
        diccionario = {
            "type": input[0].lower(),
            "value": input[1].lower(),
            "description" : input[2],
            "source" : input[3],
            "score" : "-1",
            "expiration": cambio.converter(),
            "severity": "Informational",
            "mark" : ["VT not found"],
            "name": input[1].lower()
        }
        
    return diccionario

