from multiprocessing.dummy import Array
from pymisp import ExpandedPyMISP, MISPSighting
from pymisp import MISPEvent
from sqlalchemy import null
from datetime import datetime


class misp_instance:
    def __init__(self, url, api_key) -> None:
        self.instance = ExpandedPyMISP(url, api_key, False)

    def parseTypes(self, type):
        if "ip" in type.lower():
            return "ip-src"
        return type.lower().replace('-', '')

    def setEvents(self, events, clients: list, expiration=null):
        self.events = {}
        aux = {event['info']: event for event in self.instance.events()}
        self.updates = []
        ret = []
        if len(clients) == 0:
            clients.append("All")
        to_ids = expiration != 'null'
        self.sightings = []
        for a in events.values:
            log = []
            if expiration != 'null':
                for b in a[3]:
                    sight = MISPSighting()
                    sight.from_dict(value=b, source="Expiration from CTI Manager",
                                    type=2, timestamp=datetime.fromtimestamp(int(expiration[:10])))
                    self.sightings.append(sight)
            for client in clients:
                try:
                    campaign = "client:" + client if client != "All" else a[0]
                    if campaign in self.events.keys():
                        [self.events[campaign].add_attribute(type=self.parseTypes(
                            a[1]), value=b, to_ids=to_ids, comment=a[2]) for b in a[3]]
                    else:
                        e = MISPEvent()
                        if(campaign in aux.keys()):
                            e.from_dict(Event=aux[campaign])
                            [e.add_attribute(type=self.parseTypes(
                                a[1]), value=b, comment=a[2], to_ids=to_ids) for b in a[3]]
                            self.updates.append(campaign)
                        else:
                            e.from_dict(Event={'info': campaign, 'published': False, 'Attribute': [
                                        {"type": self.parseTypes(a[1]), "value": b, "to_ids": to_ids, "comment": a[2]} for b in a[3]]})
                            e.add_tag(self.getTag())

                        self.events[campaign] = e
                    log.extend(["Added to MISP"] * len(a[3]))
                except Exception as e:
                    log.extend([e] * len(a[3]))
                    continue
            ret.extend([log[0]] * len(a[3]))
        return ret

    def getTag(self):
        IOC_CP = self.instance.get_tag(1044)

        return IOC_CP

    def getLogs(self):
        iocs = self.instance.search(
            'attributes', searchall="%Uploaded by:%")
        return [{'ioc': ioc['value'], 'user':ioc['comment'].split(
            'Uploaded by: ')[1]} for ioc in iocs['Attribute']]

    def getClients(self):
        events = self.instance.search_index(eventinfo='%' + 'client%')
        return [event['info'].split(':')[1] for event in events]

    def push(self):
        for event in self.events.values():
            if event['info'] in self.updates:
                self.instance.update_event(event)
            else:
                self.instance.add_event(event)
        for sight in self.sightings:
            self.instance.add_sighting(sight)

    def createThreatLevelTag(self):
        tag = self.getTag()

        for event in self.events:
            event['Event']['Tag'].append(
                tag - 1)

            event['Event']['timestamp'] = str(
                int(event['Event']['timestamp']) + 1)
            self.instance.update_event(event)

    def deleteAttributes(self, df):
        for a in df.values:
            attributes = self.instance.search(
                'attributes', value=a[1])['Attribute']
            att = set([b['id'] for b in attributes if b['object_id']
                      == '0' and b['to_ids'] == True])
            objects = set([b['object_id'] for b in attributes])
            for obj in objects:
                self.instance.delete_object(obj)
            for a in att:
                self.instance.delete_attribute(a)
