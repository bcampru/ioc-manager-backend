from falconpy.api_complete import APIHarness as Uber

creds = {
"client_id": "250408d06f6f473584368c9910891e9c",
"client_secret": "0AuLZJ5FvQbfTtwxGR1XnOksU9a4mz3pqN6g8H72"
}

def createIOCPayload(source: str, action: str, mark: list, desc: str, type: str, val: str, severity: str, filename: str):
    payload = {
  "comment": "Prueba de subida IOCs by Eric Guerra", 
  "indicators": [
    {
      "action": action, 
      "applied_globally": True, 
      "description": desc, 
      "expiration": "2021-12-05T12:46:23.341Z", 
      "host_groups": [""], 
      "metadata": {"filename": filename}, 
      "mobile_action": "nothing", 
      "platforms": ["windows", "mac"], 
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

   
    BODY = createIOCPayload(diccionario["source"], action, diccionario["mark"], diccionario["description"], diccionario["type"], diccionario["value"], diccionario["severity"], filename)
    response = falcon.command('indicator_create_v1', body=BODY)

    print(response)

    return response
    
