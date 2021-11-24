def create_json(diccionario, action, filename):
    
    json = {}
    json["comment"] = "Prueba de subida IOCs by Eric Guerra"
    json ["indicators"] = [
            {
            "action": action,
            "applied_globally": True,
            "description": diccionario["description"],
            "expiration": "2021-12-05T12:46:23.341Z",
            "host_groups": [
                ""
            ],
            "metadata": {
                "filename": filename
            },
            "mobile_action": "nothing",
            "platforms": [
                "windows","mac"
            ],
            "severity": diccionario["severity"],
            "source": diccionario["source"],
            "tags": diccionario["mark"],
            "type": diccionario["type"],
            "value": diccionario["value"]
            }
        ]

    return json
