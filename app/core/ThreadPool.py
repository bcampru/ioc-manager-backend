from app.core import VT
from app.core import crowdstrike
import os
import re


def add(a, filename, file):
    try:

        iocs = {"sha256": "sha256", "md5": "md5", "domain": "domain", "ipv4": "ipv4", "ipv6": "ipv6",
                "url": "url", "ip address": "ipv4", "ipv4 address": "ipv4", "ipv6 address": "ipv6", "ip": "ipv4"}

        if(a[0].lower() in iocs):
            # Comprovar que existeix alguna IP
            ipv4 = re.findall(r'[0-9]+(?:\.[0-9]+){3}', a[1])
            if(len(ipv4) > 0):
                a[1] = ipv4[0]
                a[0] = "ipv4"

            llista_type = iocs[a[0]]
            llista_value = a[1]
            llista_campanya = a[2]
            diccionario = VT.virustotal(a)

            result = crowdstrike.crowd(diccionario, "detect", filename)

            if(int(result["status_code"]) >= 400):
                llista_bool = "No"
                try:
                    llista_comprovacio = result["body"]["errors"][0]["message"]
                except:
                    llista_comprovacio = "falla " + result["status_code"]
            else:
                file.write(a[0] + " " + a[1] + " " +
                           diccionario["name"] + os.linesep)
                llista_comprovacio = iocs[a[0]] + " correctly added"
                llista_bool = "Yes"

            return llista_type, llista_comprovacio, llista_value, llista_bool, llista_campanya

        return a[0], "Type Is Not Valid", a[1], "No", ""

    except:
        return a[0], "No", a[1], "IOC Malformed", ""


def update_concurrent(a, filename, file, action):
    try:

        iocs = {"sha256": "sha256", "md5": "md5", "domain": "domain", "ipv4": "ipv4", "ipv6": "ipv6", "url": [
            "ipv4", "domain"], "ip address": "ipv4", "ipv4 address": "ipv4", "ipv6 address": "ipv6", "ip": "ipv4"}

        if(a[0].lower() in iocs):
            # Comprovar que existeix alguna IP
            ipv4 = re.findall(r'[0-9]+(?:\.[0-9]+){3}', a[1])
            if(len(ipv4) > 0):
                a[1] = ipv4[0]
                a[0] = "ipv4"

            action = "prevent" if iocs[a[0]
                                       ] == "sha256" or iocs[a[0]] == "md5" else "detect"
            llista_type = iocs[a[0]]
            llista_value = a[1]
            llista_campanya = a[2]
            diccionario = VT.virustotal(a)

            result = crowdstrike.updateIoc(diccionario, action, filename)

            if(int(result) == 0):
                llista_bool = "No"
                llista_comprovacio = "Not found in CrowdStrike"
            else:
                file.write(a[0] + " " + a[1] + " " +
                           diccionario["name"] + os.linesep)
                llista_comprovacio = "Hash correctly updated"
                llista_bool = "Yes"

            return llista_type, llista_comprovacio, llista_value, llista_bool, llista_campanya

        return a[0], "Type Is Not Valid", a[1], "No"

    except:
        return a[0], "No", a[1], "IOC Malformed"


def delete_concurrent(a):
    crowdstrike.delete_crowd(a[1])
