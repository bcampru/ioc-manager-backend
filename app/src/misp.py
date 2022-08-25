from pymisp import ExpandedPyMISP
from pymisp import MISPEvent


class misp_instance:
    def __init__(self, url, api_key) -> None:
        self.instance = ExpandedPyMISP(url, api_key, False)

    def parseTypes(self, type):
        if "ip" in type.lower():
            return "ip-src"
        return type.lower().replace('-', '')

    def setEvents(self, events):
        self.events = {}
        aux = {event['info']: event for event in self.instance.events()}
        self.updates = []
        ret = []
        for a in events.values:
            try:
                campaign = a[0]
                if campaign in self.events.keys():
                    self.events[campaign].from_dict(Event={'info': campaign, 'published': True, 'Attribute': [
                                                    {"type": self.parseTypes(a[1]), "value":b, "to_ids": False, "comment":a[2]} for b in a[3]]})
                else:
                    e = MISPEvent()
                    if(campaign in aux.keys()):
                        e.from_dict(Event=aux[campaign])
                        [e.add_attribute(type=self.parseTypes(
                            a[1]), value=b, comment=a[2]) for b in a[3]]
                        self.updates.append(campaign)
                    else:
                        e.from_dict(Event={'info': campaign, 'published': True, 'Attribute': [
                                    {"type": self.parseTypes(a[1]), "value":b, "to_ids": False, "comment":a[2]} for b in a[3]]})
                        e.add_tag(self.getTag())
                    self.events[campaign] = e
                ret.extend(["Added to MISP"]*len(a[3]))
            except Exception as e:
                ret.extend([e]*len(a[3]))
                continue
        return ret

    def getTag(self):
        IOC_CP = self.instance.get_tag(1044)

        return IOC_CP

    def push(self):
        for event in self.events.values():
            if event['info'] in self.updates:
                self.instance.update_event(event)
            else:
                self.instance.add_event(event)

    def createThreatLevelTag(self):
        tag = self.getTag()

        for event in self.events:
            event['Event']['Tag'].append(
                tag - 1)

            event['Event']['timestamp'] = str(
                int(event['Event']['timestamp'])+1)
            self.instance.update_event(event)
