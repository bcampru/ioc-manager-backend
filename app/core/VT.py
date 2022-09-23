import requests
from app.core import converter
import numpy as np


def virustotal(input):

    if(len(input) == 2):
        input = np.append(input, ["", ""])
    if(len(input) == 3):
        input = np.append(input, "")

    dic = {'sha256': "files/", 'md5': "files/", 'url': "urls/",
           'domain': "domains/", "ipv4": "ip_addresses/"}

    variable = dic[input[0]]

    url = 'https://www.virustotal.com/api/v3/' + variable + str(input[1])
    headeris = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        'x-apikey': '8efcd2ce48b4139ff2033d8e6c17de92cca24661ea4236e7b1feda524b01b0d6'
    }
    try:
        r = requests.get(url, headers=headeris).json()
    except:
        print("error en VT")
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

        tipo = set(tipo)

        overall = score / max_detect

        if(overall > 0.9):
            severity = "critical"
        else:
            if(overall > 0.30):
                severity = "high"
            else:
                if(overall > 0.05):
                    severity = "medium"
                else:
                    severity = "none"

        name = input[1]
        if(variable == "files/"):
            try:
                name = r['data']['attributes']['type_description']
            except:
                print("error getting Name File")

        diccionario = {
            "type": input[0],
            "value": input[1],
            "score": str(score),
            "total": str(max_detect),
            "mark": list(tipo),
            "antiVir": str(herramientas)[1:-1].lower(),
            "overall": overall,
            "severity": severity,
            "description": str(input[2]),
            "source": str(input[3]),
            "name": name,
            "expiration": cambio.converter()
        }

    except:
        diccionario = {
            "type": input[0],
            "value": input[1],
            "description": input[2],
            "source": input[3],
            "score": "-1",
            "expiration": cambio.converter(),
            "severity": "Informational",
            "mark": ["VT not found"],
            "name": input[1]
        }

    return diccionario
