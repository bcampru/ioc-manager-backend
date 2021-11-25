import requests
import json
import ipaddress

def virustotal(input):
    if (input[0] == 'SHA256') or (input[0] == 'MD5'):
        variable = "files/"
    else:
        if(input[0] == 'URL'):
            variable = "urls/"
        elif(input[0] == 'Domain'):
            variable = "domains/"

    url = 'https://www.virustotal.com/api/v3/' + variable + str(input[1])
    headeris = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        'x-apikey': 'f2449cde5f7e1205caa9010c737184ddae989bdf275f6f43b71f1a7a24c44204'
    }

    r = requests.get(url, headers=headeris).json()

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
            name = r['data']['attributes']['meaningful_name']

        diccionario = {
            "type": input[0].lower(),
            "value": input[1].lower(),
            "score" : str(score),
            "total" : str(max_detect),
            "mark" : tipo[1:-1],
            "antiVir" : str(herramientas)[1:-1].lower(),
            "overall" : overall,
            "severity" : severity,
            "description" : input[2],
            "source" : input[3],
            "name": name  
        }

    except:
        diccionario = {
            "type": input[0].lower(),
            "value": input[1].lower(),
            "description" : input[2],
            "source" : input[3],
            "score" : "-1"
        }
        
    return diccionario

