import json
import os
from jinja2 import Template
import logging
class ExportIncident:
    def __init__(self, incident):
        self.incident = incident
    async def export_report(self):
        incident_id = self.incident.get("incident_id")
        incident_json = json.dumps(self.incident,indent=4)
        incident = self.incident
        try:
            with open(f"out/incidents/{incident_id}.log", "a") as w:
                w.write(incident_json)
            logging.info(f"Json Report exported: out/incidents/{incident_id}.log")
        except FileNotFoundError:
            os.makedirs("out/incidents")
            with open(f"out/incidents/{incident_id}.log", "a") as w:
                w.write(incident_json)
            logging.info("Incidents folder created")
        try:
            with open("template/incident.ji2") as f:
                incident_template = f.read()
            with open(f"out/summaries/{incident_id}.md", "w") as w:
                template = Template(incident_template)
                markdown_output = template.render(incident=incident)
                w.write(markdown_output)
            logging.info(f"MD Report exported: out/summaries/{incident_id}.md")
        except FileNotFoundError:
            os.makedirs("out/summaries")
            with open(f"out/summaries/{incident_id}.md", "w") as w:
                template = Template(incident_template)
                markdown_output = template.render(incident=incident)
                w.write(markdown_output)
            logging.info("Summaries folder created")
        except FileExistsError: logging.info("Path already exists")
        except Exception as e: logging.error(e)