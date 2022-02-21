from falconpy.api_complete import APIHarness as Uber
from falconpy.ioc import IOC as IOC
from dotenv import load_dotenv
import os

load_dotenv()

creds = {
    "client_id": os.getenv("client_id"),
    "client_secret": os.getenv("client_secret")
}


def createIOCPayload(source: str, action: str, mark: list, desc: str, type: str, val: str, severity: str, filename: str, expiration: str):
    payload = {
        "comment": "IOCs Weekly added to CrowdStrike",
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

    BODY = createIOCPayload(diccionario["source"], action, diccionario["mark"], diccionario["description"],
                            diccionario["type"], diccionario["value"], diccionario["severity"], filename, diccionario["expiration"])
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
        delete_crowd(diccionario["value"])
        crowd(diccionario, action, filename)

    return len(response['body']['resources'])


def getIoc(ioc):
    falcon = IOC(creds=creds)
    response = falcon.indicator_get_v1(ids=ioc)
    print(response)
