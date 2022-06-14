class misp_instance:
    def __init__(self, url, api_key) -> None:
        self.instance = ExpandedPyMISP(url, api_key, False)

    def getLevels(self):
        high = self.instance.get_tag(1145)
        low = self.instance.get_tag(1146)
        medium = self.instance.get_tag(1147)
        undefined = self.instance.get_tag(1148)

        return [high, medium, low, undefined]

    def getFilteredEvents(self, tagFilter, first_date=False):
        if(first_date == False):
            return self.instance.search(include_sightings=False, include_correlations=False, include_decay_score=False, controller='events', tags=tagFilter)
        return self.instance.search(include_sightings=False, include_correlations=False, include_decay_score=False, controller='events', tags=tagFilter, date_from=first_date)

    def getFilteredAttributes(self, first_date):
        return self.instance.search(include_sightings=False, include_correlations=False, include_decay_score=False, limit=5, controller='attributes', date_from=first_date)

    def push(self, events):
        for event in events:
            self.instance.add_event(event)

    def createThreatLevelTag(self):
        levels = self.getLevels()

        filter = ['!ThreatLevel:low', '!ThreatLevel:medium',
                  '!ThreatLevel:high', '!ThreatLevel:undefined']
        events = self.getFilteredEvents(filter)

        for event in events:
            event['Event']['Tag'].append(
                levels[int(event["Event"]["threat_level_id"]) - 1])

            event['Event']['timestamp'] = str(
                int(event['Event']['timestamp'])+1)
            self.instance.update_event(event)
