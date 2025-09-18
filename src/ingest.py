import json
import logging
from src.enrichment import Enrichment
from src.triage import Triage

class AlertIngest:
    def __init__(self,file):
        self.alert = file
    async def load_alert(self):
        logging.info(f"Loading Alert {self.alert}")
        with open(self.alert, "r") as alert:
            alert_data = json.load(alert)
        await self.normalizealert(alert_data)

    @staticmethod
    async def normalizealert(alert_data):
        incident = {}
        incident.update({"incident_id":f"inc-{alert_data["alert_id"]}"})
        incident.update({"source_alert":alert_data})
        logging.info("Normalize Alert")
        for key in alert_data.keys():
            match key:
                case "asset":
                    value = alert_data.get(key)
                    asset = {
                        "device_id": value.get("device_id"),
                        "hostname": value.get("hostname"),
                        "ip": value.get("ip")
                    }
                    incident.update({"asset":asset})
                case "indicators":
                    value = alert_data.get(key)
                    indicators = []
                    for v in value.keys():
                        indicator = {
                            "type": v,
                            "value": (value.get(v)[0] if value.get(v) and len(value.get(v)) > 0 else None)
                        }
                        indicators.append(indicator)
                        incident.update({"indicators":indicators})
                case _:
                    value = alert_data.get(key)
                    incident.update({key:value})
        logging.info("Starting enrichment")
        enrich = Enrichment(incident)
        await enrich.enrich()
        logging.info("Enrichment finished")
        triage = Triage(incident)
        await triage.starttriage()
