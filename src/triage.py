import logging
from src.actions import Action
from src.exportincident import ExportIncident


class Triage:
    def __init__(self,incident):
        self.incident = incident
    async def starttriage(self):
        logging.info("Starting Triage")
        severity = 0
        base = self.incident["type"]
        match base:
            case "Malware":
                severity+= 70
            case "Phishing":
                severity+= 60
            case "Beaconing":
                severity+= 65
            case "CredentialAccess":
                severity+= 75
            case "C2":
                severity+= 80
            case _:
                severity+= 40
                logging.info(f"Unknown type")
        logging.info(f"{self.incident['incident_id']}, type {self.incident['type']} current severity {severity}")
        triage = {
            "severity": severity,
            "tags": [],
            "bucket": None,
            "supressed": None
        }
        self.incident.update({"triage": triage})
        await self.verifyallowlist(severity)
        await self.mitretagging()

        if self.incident.get("triage")["severity"] > 70 and self.incident.get("asset")["allowlisted"] == False:
            action = Action(self.incident)
            await action.isolate()
        export = ExportIncident(self.incident)
        await export.export_report()

    async def verifyallowlist(self,severity):
        from yaml import safe_load
        with open("configs/allowlists.yml") as allowlist:
            allowlist = safe_load(allowlist)
        device_id = self.incident["asset"]["device_id"]

        try:
            allowlist["assets"]["device_ids"].index(device_id)
            severity-=25
            logging.info(f"{self.incident['incident_id']}, type {self.incident['type']} current severity {severity}")
            self.incident["asset"]["allowlisted"] = True
            self.incident["severity"] = severity
        except ValueError:
            logging.info(f"Device {device_id} is not in allowlist")
            self.incident["asset"]["allowlisted"] = False
        total_ioc = len(self.incident["indicators"])
        total_allowlisted=0
        ioc_verified = 0
        for indicator in self.incident['indicators']:
                if indicator["value"] is not None:
                        if "hxxp" in indicator["value"]:
                            undefanged =  indicator["value"].replace("hxxp","http").replace("[.]",".")
                            if undefanged in allowlist['indicators'][indicator["type"]]:
                                indicator.update({"allowlisted":True})
                                severity-=25
                                if indicator.get("risk")['reputation'] == "malicious":
                                    severity += 20
                                    ioc_verified += 5
                                    total_allowlisted+=1
                                if indicator.get("risk")['reputation'] == "suspicious":
                                    severity += 20
                                    ioc_verified += 5
                                    total_allowlisted += 1
                                logging.info(f"{self.incident['incident_id']}, type {self.incident['type']} current severity {severity}")
                            else:
                                indicator.update({"allowlisted":False})
                        else:
                            if indicator["value"] in allowlist['indicators'][indicator["type"]]:
                                indicator.update({"allowlisted": True})
                                severity -= 25
                                if indicator.get("risk")['reputation'] == "malicious":
                                    severity += 20
                                    ioc_verified += 5
                                    total_allowlisted += 1
                                if indicator.get("risk")['reputation'] == "suspicious":
                                    severity += 10
                                    ioc_verified += 5
                                    total_allowlisted += 1
                                logging.info(f"{self.incident['incident_id']}, type {self.incident['type']} current severity {severity}")
                            else:
                                indicator.update({"allowlisted": False})
        if total_ioc == total_allowlisted:
            self.incident["triage"]["supressed"] = True
            self.incident["triage"]["severity"] = 0
        else: self.incident["triage"]["supressed"] = False
        bucket = self.incident["triage"]["severity"]
        if bucket < 0: bucket = 0
        match bucket:
            case 0:
                self.incident["triage"]["bucket"] = "Supressed"
            case sev if 1 <= sev <= 39:
                self.incident["triage"]["bucket"] = "Low"
            case sev if 40 <= sev <= 69:
                self.incident["triage"]["bucket"] = "Medium"
            case sev if 70 <= sev <= 89:
                self.incident["triage"]["bucket"] = "High"
            case sev if 90 <= sev <= 100:
                self.incident["triage"]["bucket"] ="Critical"
        severity = severity+ioc_verified
        self.incident["triage"]["severity"] = severity
        return self.incident

    async def mitretagging(self):
        from yaml import safe_load
        with open("configs/mitre_map.yml") as mitre_map:
            mitre_map = safe_load(mitre_map)
        incident_type = self.incident["type"]
        mitre = {
            "techniques" : []
        }
        if incident_type in mitre_map["types"]:
            mitre.update({"techniques": mitre_map.get("types")[incident_type]})
            self.incident.update(mitre)
        else:
            mitre.update({"techniques": mitre_map.get("types")["defaults"]})
            self.incident.update(mitre)
