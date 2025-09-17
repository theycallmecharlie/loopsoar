import json
import logging
import os
import re
class Enrichment:
    def __init__(self,incident):
        self.incident = incident

    async def enrich(self):
        iocs = self.incident['indicators']
        logging.info("Verifying Artifacts")
        for ioc in iocs:
            match(ioc["type"]):
                case "ipv4":
                    logging.info(f"IP {ioc.get("value")} enrich")
                    if ioc.get("value") is not None:
                        mock = "mocks/it/ip"
                        files = await self.loadmock(mock)
                        for file in files:
                            if ioc["value"] in file:
                                filepath = f"{mock}/{file}"
                                if ioc["value"] in file:
                                    with open(filepath, "r") as report_data:
                                        report_data = json.load(report_data)
                                    report = {
                                        "confidence": report_data.get("confidence"),
                                        "risk": report_data.get("risk"),
                                        "sightings": report_data.get("sightings"),
                                        "sources": ["Anomali IP"]
                                    }
                                    ioc.update({"risk":report})
                case "domains":
                    logging.info(f"Domain {ioc.get("value")} enrich")
                    if ioc.get("value") is not None:
                        mock = "mocks/it/domain"
                        files = await self.loadmock(mock)
                        for file in files:
                            filepath = f"{mock}/{file}"
                            domain = ioc["value"]
                            if domain in file:
                                if "http" in domain:
                                    domain = re.search("(https|http)://([\w.\-]+)/", ioc["value"])
                                    domain = domain.group(2)
                                else:
                                    if ioc["value"] in file:
                                        with open(filepath, "r") as report_data:
                                            report_data = json.load(report_data)
                                        report = {
                                                "reputation": report_data.get("reputation"),
                                                "categories": report_data.get("categories"),
                                                "score": report_data.get("score"),
                                                "sources": ["Defender TI"]
                                        }
                                        ioc.update({"risk": report})
                    else:
                        pass
                case "sha256":
                    if ioc.get("value") is not None:
                        logging.info(f"Hash {ioc.get("value")} enrich")
                        if ioc.get("value") is not None:
                            mock = "mocks/it/hash"
                            files = await self.loadmock(mock)
                            for file in files:
                                if ioc["value"] in file:
                                    filepath = f"{mock}/{file}"
                                    if ioc["value"] in file:
                                        with open(filepath, "r") as report_data:
                                            report_data = json.load(report_data)
                                        report = {
                                            "classification": report_data.get("classification"),
                                            "threat_name": report_data.get("threat_name"),
                                            "score": report_data.get("score"),
                                            "sources": ["Reversing Labs"]
                                        }
                                        ioc.update({"risk": report})
                case "urls":
                    if ioc.get("value") is not None:
                        logging.info(f"URL {ioc.get("value")} enrich")
                        mock = "mocks/it/domain"
                        files = await self.loadmock(mock)
                        for file in files:
                                filepath = f"{mock}/{file}"
                                domain = ioc["value"]
                                if "http" in domain:
                                    domain = re.search("(https|http)://([\w.\-]+)/", ioc["value"])
                                    domain = domain.group(2)
                                    if domain in file:
                                        with open(filepath, "r") as report_data:
                                            report_data = json.load(report_data)
                                        report = {
                                            "reputation": report_data.get("reputation"),
                                            "categories": report_data.get("categories"),
                                            "score": report_data.get("score"),
                                            "sources": ["Defender TI"]
                                        }
                                        ioc.update({"risk": report})
                                        defang = ioc["value"].replace("http","hxxp").replace(".","[.]")
                                        ioc["value"] = defang
                                    else:
                                        ioc.update({"response": "Artifact not found on provider"})
                case _:
                    logging.error("Unexpected artifact")
    @staticmethod
    async def loadmock(mock):
        files = [f for f in os.listdir(mock) if os.path.isfile(os.path.join(mock, f))]
        return files


