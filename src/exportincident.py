import json
import os
from jinja2 import Template
class exportincident:
    def __init__(self, incident):
        self.incident = incident
    async def export_report(self):
        incident_id = self.incident.get("incident_id")
        incident_json = json.dumps(self.incident,indent=4)
        incident = self.incident
        print(incident_json)
        try:
            with open(f"out/incidents/{incident_id}.log", "a") as w:
                w.write(incident_json)
        except FileNotFoundError:
            os.makedirs("out/incidents")
            with open(f"out/summaries/{incident_id}.log", "a") as w:
                w.write(incident_json)
        try:
            with open("template/incident.ji2") as f:
                incident_template = f.read()
            with open(f"out/summaries/{incident_id}.md", "w") as w:
                template = Template(incident_template)
                markdown_output = template.render(incident=incident)
                w.write(markdown_output)
        except FileNotFoundError:
            os.makedirs("out/summaries")
            with open(f"out/summaries/{incident_id}.md", "w") as w:
                template = Template(incident_template)
                markdown_output = template.render(incident=incident)
                w.write(markdown_output)
