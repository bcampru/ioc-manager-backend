from falconpy.api_complete import APIHarness as Uber
from falconpy.ioc import IOC as IOC

creds = {
"client_id": "45b504f3c6ee44f3957c8ee9993179e8",
"client_secret": "DjIps7aT8E2d5gh9w06QAMoSbKrOuFZyXRlW431t"
}

def createIOCPayload(source: str, action: str, mark: list, desc: str, type: str, val: str, severity: str, filename: str, expiration: str):
    payload = {
    "comment": "Prueba de subida IOCs by Eric Guerra", 
    "indicators": [
    {
      "action": action, 
      "applied_globally": True, 
      "description": desc, 
      "expiration": expiration, 
      "host_groups": [""], 
      "metadata": {"filename": filename}, 
      "mobile_action": "nothing", 
      "platforms": ["windows", "linux"], 
      "severity": severity, 
      "source": source, 
      "tags": mark, 
      "type": type, 
      "value": val
      }]
    }
    return payload

def crowd(diccionario, action, filename):
    falcon = Uber(creds=creds)

   
    BODY = createIOCPayload(diccionario["source"], action, diccionario["mark"], diccionario["description"], diccionario["type"], diccionario["value"], diccionario["severity"], filename, diccionario["expiration"])
    response = falcon.command('indicator_create_v1', body=BODY)


    print(response)

    return response
    

def delete_crowd(ioc):
    falcon = IOC(creds=creds)
    aid = falcon.indicator_delete_v1(filter=f"value:'{ioc}'")

    print(aid)
    return aid

def updateIoc(diccionario, action, filename):
    falcon = IOC(creds=creds)
    ioc = diccionario["value"]
    response = falcon.indicator_search(filter=f"value:'{ioc}'")
    if (len(response['body']['resources']) > 0):
        falcon.indicator_update_v1(action="prevent", value="9344afc63753cd5e2ee0ff9aed43dc56")
        delete_crowd(diccionario["value"])
        crowd(diccionario, action, filename)

    return len(response['body']['resources'])

def getIoc(ioc):
    falcon = IOC(creds=creds)
    response = falcon.indicator_get_v1(ids=ioc)
    print(response)
