from pymisp import ExpandedPyMISP
from pymisp import MISPEvent


class misp_instance:
    def __init__(self, url, api_key) -> None:
        self.instance = ExpandedPyMISP(url, api_key, False)

    def parseTypes(self, type):
        if "ip" in type:
            return "domain|ip"
        return type.lower().replace('-', '')

    def setEvents(self, events):
        self.events = {}
        for a in events.values:
            try:
                campaign = a[0]
                if campaign in self.events.keys():
                    self.events[campaign].from_dict(Event={'info': campaign, 'Attribute': [
                                                    {"type": self.parseTypes(a[1]), "value":b, "to_ids": True, "comment":a[2]} for b in a[3]]})
                else:
                    e = MISPEvent()
                    e.from_dict(Event={'info': campaign, 'published': True, 'Attribute': [
                                {"type": self.parseTypes(a[1]), "value":b, "to_ids": True, "comment":a[2]} for b in a[3]]})
                    e.add_tag(self.getTag())
                    self.events[campaign] = e
            except:
                continue

    def getTag(self):
        IOC_CP = self.instance.get_tag(1044)

        return IOC_CP

    def push(self):
        for event in self.events.values():
            self.instance.add_event(event)

    def createThreatLevelTag(self):
        tag = self.getTag()

        for event in self.events:
            event['Event']['Tag'].append(
                tag - 1)

            event['Event']['timestamp'] = str(
                int(event['Event']['timestamp'])+1)
            self.instance.update_event(event)
