import requests
import csv
import os
from datetime import datetime

file_cves = "cves.txt"
file_result = "result.csv"

fieldnames = [
    "identifier",
    "title",
    "scopeAndContent",
    "creationDates",
    "subjectAccessPoints",
    "subjectAccessPoints",
    "levelOfDescription",
    "language",
    "descriptionStatus",
    "levelOfDetail",
    "revisionHistory",
    "languageOfDescription",
    "subjectAccessPoints",
    "placeAccessPoints",
    "nameAccessPoints",
    "genreAccessPoints",
    "sources"
]

def formatDate(date):
    dt = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%f")
    return dt.strftime("%d/%m/%Y %H:%M:%S")

def getTitle():
    title = data.get("cisaVulnerabilityName", [])
    
    if title:
        return title
    else:
        return ". ".join(d.get("value", "") for d in descriptions if d.get("lang") == "en")

with open(file_cves, "r") as file:
    cve_ids = [line.strip() for line in file if line.strip()]

if not os.path.exists(file_result):
    with open(file_result, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=',')
        writer.writeheader()

for cve_id in cve_ids:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            with open(file_result, "a", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=',')
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    metrics = cve.get("metrics", {})
                    descriptions = cve.get("descriptions", [])
                    references = cve.get("references", [])

                    description = f"""
CVE ID: {cve.get("id", "")}
Source: {cve.get("sourceIdentifier", "")}
Published: {formatDate(cve.get("published", ""))}
Last Modified: {formatDate(cve.get("lastModified", ""))}
Status: {cve.get("vulnStatus", "")}

Description:
{". ".join(d.get("value", "") for d in descriptions if d.get("lang") == "en")}

CVSS v3:
- Base Score: {metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "")}
- Severity: {metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "")}
- Vector String: {metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("vectorString", "")}

CVSS v2:
- Base Score: {metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore", "")}
- Severity: {metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseSeverity", "")}
- Vector String: {metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("vectorString", "")}

CWE: {"; ".join([w.get("description", [{}])[0].get("value", "") for w in cve.get("weaknesses", [])])}

References:
{"\n".join([ref.get("url", "") for ref in references])}
                    """.strip()

                    row = {
                        "identifier": cve.get("id", ""),
                        "title": getTitle(),
                        "scopeAndContent": description,
                        "creationDates": cve.get("published", ""),
                        "subjectAccessPoints": "NVD",
                        "subjectAccessPoints": "Security",
                        "levelOfDescription": "Item",
                        "language": "en",
                        "descriptionStatus": "Final",
                        "levelOfDetail": "Partial",
                        "revisionHistory": "12/01/2025",
                        "languageOfDescription": "en",
                        "subjectAccessPoints": "CVE",
                        "placeAccessPoints": "USA",
                        "nameAccessPoints": "CVE of RCE",
                        "genreAccessPoints": "RCE",
                        "sources": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    }
                    writer.writerow(row)
            print(f"{cve_id} data saved successfully!")
        else:
            print(f"No vulnerabilities found in {cve_id}.")
    else:
        print(f"Error accessing NVD: {response.status_code}")

print("CSV file formatted for AtoM is ready!")
