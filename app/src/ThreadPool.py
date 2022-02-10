from turtle import update
from app.src import VT
from app.src import crowdstrike
import os
import re


def add(a, csv, file):
    try:
        if (a[0] == 'SHA-256') or (a[0] == 'MD5'):
            a[0] = a[0].replace("-", "")
            llista_type=a[0]
            llista_value=a[1]
            diccionario = VT.virustotal(a)

            if(diccionario["score"] != '0' and diccionario["score"] != '-1'):

                result = crowdstrike.crowd(diccionario, "detect", csv.filename)
            
                if(int(result["status_code"]) >= 400):
                    llista_bool="No"
                    try:
                        llista_comprovacio=result["body"]["resources"][0]["message"]
                    except:
                        llista_comprovacio="falla " + result
                else:
                    file.write(a[0] + " " + a[1] + " " + diccionario["name"] + os.linesep)
                    llista_comprovacio="Hash correctly added"
                    llista_bool="Yes"
            else:
                llista_bool = "No"
                if(diccionario["score"] == '0'):
                    llista_comprovacio = "Hash wasn't added as it isn't harmfull"
                
                elif(diccionario["score"] == '-1'):
                    llista_comprovacio = "Hash wasn't added, not found in VirusTotal"
            

        else:
            a[1] = a[1].replace("[", "")
            a[1] = a[1].replace("]", "")
            llista_type=a[0]
            llista_value=a[1]

            if (a[0] == 'Domain'):
                diccionario = VT.virustotal(a)
                if(diccionario["score"] != '0' and diccionario["score"] != '-1'):
                    
                    result = crowdstrike.crowd(diccionario, "detect", csv.filename)
                    
                    if(int(result["status_code"]) >= 400):
                        llista_bool="No"
                        llista_comprovacio=result["body"]["resources"][0]["message"]
                    else:
                        file.write(a[0] + " " + a[1] + os.linesep)
                        llista_comprovacio="correctly added"
                        llista_bool="Yes"
                else:
                    llista_bool="No"
                    if(diccionario["score"] == '0'):
                        llista_comprovacio="Domain wasn't added as it isn't harmfull"
                
                    elif(diccionario["score"] == '-1'):
                        llista_comprovacio="Domain wasn't added, not found in VirusTotal"
            else:
                if(a[0] == "URL"):
                    ipv4 = re.findall( r'[0-9]+(?:\.[0-9]+){3}', a[1])
                    if(len(ipv4)>0):
                        a[1] = ipv4[0]
                        a[0] = "ipv4"
                        llista_type=a[0]
                        llista_value=a[1]
                        diccionario = VT.virustotal(a)

                        if(diccionario["score"] != '0' and diccionario["score"] != '-1'):

                            result = crowdstrike.crowd(diccionario, "detect", csv.filename)
                        
                            if(int(result["status_code"]) >= 400):
                                llista_bool="No"
                                try:
                                    llista_comprovacio=result["body"]["resources"][0]["message"]
                                except:
                                    llista_comprovacio="falla " + result
                            else:
                                file.write(a[0] + " " + a[1] + " " + diccionario["name"] + os.linesep)
                                llista_comprovacio="IP correctly added"
                                llista_bool="Yes"
                        else:
                            llista_bool = "No"
                            if(diccionario["score"] == '0'):
                                llista_comprovacio = "IP wasn't added as it isn't harmfull"
                            
                            elif(diccionario["score"] == '-1'):
                                llista_comprovacio = "IP wasn't added, not found in VirusTotal"
                    else:
                        llista_comprovacio="Type is not valid"
                        llista_bool="No" 
                else:
                    llista_comprovacio="Type is not valid"
                    llista_bool="No"
    except:
        return a[0], "-", a[1], "-"

    return llista_type, llista_comprovacio, llista_value, llista_bool

def update_concurrent(a, csv, file, action):
    if (a[0] == 'SHA-256') or (a[0] == 'MD5'):
        a[0] = a[0].replace("-", "")
        llista_type=a[0]
        llista_value=a[1]
        diccionario = VT.virustotal(a)

        if(diccionario["score"] != '0' and diccionario["score"] != '-1'):

            result = crowdstrike.updateIoc(diccionario, action, csv.filename)
        
            if(int(result) == 0):
                llista_bool="No"
                llista_comprovacio="Not found in CrowdStrike"
            else:
                file.write(a[0] + " " + a[1] + " " + diccionario["name"] + os.linesep)
                llista_comprovacio="Hash correctly updated"
                llista_bool="Yes"
        else:
            llista_bool="No"
            if(diccionario["score"] == '0'):
                llista_comprovacio="Hash wasn't updated as it isn't harmfull"
            
            elif(diccionario["score"] == '-1'):
                llista_comprovacio="Hash wasn't updated, not found in VirusTotal and CrowdStrike"

    else:
        a[1] = a[1].replace("[", "")
        a[1] = a[1].replace("]", "")
        llista_type=a[0]
        llista_value=a[1]

        if (a[0] == 'Domain'):
            diccionario = VT.virustotal(a)
            if(diccionario["score"] != '0' and diccionario["score"] != '-1'):
                
                result = crowdstrike.updateIoc(diccionario, action, csv.filename)
                
                if(int(result) == 0):
                    llista_bool="No"
                    llista_comprovacio="Not found in CrowdStrike"
                else:
                    file.write(a[0] + " " + a[1] + os.linesep)
                    llista_comprovacio="correctly updated"
                    llista_bool="Yes"
            else:
                llista_bool="No"
                if(diccionario["score"] == '0'):
                    llista_comprovacio="Domain wasn't updated as it isn't harmfull"
            
                elif(diccionario["score"] == '-1'):
                    llista_comprovacio="Domain wasn't updated, not found in VirusTotal and CrowdStrike"
        else:
            if(a[0] == "URL"):
                ipv4 = re.findall( r'[0-9]+(?:\.[0-9]+){3}', a[1])
                if(len(ipv4>0)):
                    a[1] = ipv4[0]
                    a[0] = "ipv4"
                    llista_type=a[0]
                    llista_value=a[1]
                    diccionario = VT.virustotal(a)

                    if(diccionario["score"] != '0' and diccionario["score"] != '-1'):

                        result = crowdstrike.updateIoc(diccionario, action, csv.filename)
                    
                        if(int(result["status_code"]) >= 400):
                            llista_bool="No"
                            try:
                                llista_comprovacio=result["body"]["resources"][0]["message"]
                            except:
                                llista_comprovacio="falla " + result
                        else:
                            file.write(a[0] + " " + a[1] + " " + diccionario["name"] + os.linesep)
                            llista_comprovacio="IP correctly added"
                            llista_bool="Yes"
                    else:
                        llista_bool = "No"
                        if(diccionario["score"] == '0'):
                            llista_comprovacio = "IP wasn't added as it isn't harmfull"
                        
                        elif(diccionario["score"] == '-1'):
                            llista_comprovacio = "IP wasn't added, not found in VirusTotal"
                else:
                    llista_comprovacio="Type is not valid"
                    llista_bool="No" 
            else:
                llista_comprovacio="Type is not valid"
                llista_bool="No"

    return llista_type, llista_comprovacio, llista_value, llista_bool


def delete_concurrent(a):
    a[0] = a[0].replace("-", "")
    a[1] = a[1].replace("[", "")
    a[1] = a[1].replace("]", "")
    crowdstrike.delete_crowd(a[1])