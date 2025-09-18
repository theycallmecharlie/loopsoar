from time import time
import os
class Action:
    def __init__(self, incident):
        self.incident = incident


    async def isolate(self):
        device_id = self.incident.get("asset").get("device_id")
        incident_id = self.incident.get("incident_id")
        result = "isolated"
        iso_ts = int(time())
        actions = {
            "device_id": device_id,
            "hostname": self.incident.get("asset").get("hostname"),
            "ip": self.incident.get("asset").get("ip"),
            "incident_id": incident_id,
            "result": result,
            "iso_ts": iso_ts
        }
        self.incident.update({"actions": actions})
        log = f"{iso_ts} isolate device_id={device_id} incident={incident_id} result={result}\n"
        try:
            with open("out/isolation.log","a") as w:
                w.write(log)
        except FileNotFoundError:
            os.makedirs("out")
            with open("out/isolation.log","a") as w:
                w.write(log)