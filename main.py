import requests
import csv
import os

file_cves = "cves.txt"
file_result = "result.csv"

fieldnames = [
    "cve_id",
    "sourceIdentifier",
    "published",
    "lastModified",
    "vulnStatus",
    "description",
    "cvss_v3_baseScore",
    "cvss_v3_baseSeverity",
    "cvss_v3_vectorString",
    "cvss_v2_baseScore",
    "cvss_v2_baseSeverity",
    "cvss_v2_vectorString",
    "cwe",
    "references"
]

with open(file_cves, "r") as file:
    cve_ids = [line.strip() for line in file if line.strip()]   

if not os.path.exists(file_result):
    with open(file_result, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
        writer.writeheader()

for cve_id in cve_ids:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
 
            with open(file_result, "a", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')

                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    metrics = cve.get("metrics", {})
                    descriptions = cve.get("descriptions", [])
                    references = cve.get("references", [])

                    row = {
                        "cve_id": cve.get("id", ""),
                        "sourceIdentifier": cve.get("sourceIdentifier", ""),
                        "published": cve.get("published", ""),
                        "lastModified": cve.get("lastModified", ""),
                        "vulnStatus": cve.get("vulnStatus", ""),
                        "description": ". ".join(d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                        "cvss_v3_baseScore": metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", ""),
                        "cvss_v3_baseSeverity": metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", ""),
                        "cvss_v3_vectorString": metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("vectorString", ""),
                        "cvss_v2_baseScore": metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore", ""),
                        "cvss_v2_baseSeverity": metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseSeverity", ""),
                        "cvss_v2_vectorString": metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("vectorString", ""),
                        "cwe": ", ".join([w.get("description", [{}])[0].get("value", "") for w in cve.get("weaknesses", [])]),
                        "references": ", ".join([ref.get("url", "") for ref in references])
                    }
                    writer.writerow(row)

            print(f"{cve_id} data saved successfully!")
        else:
            print(f"No vulnerabilities found in {cve_id}.")
    else:
        print(f"Error accessing NVD: {response.status_code}")

print("Csv file finished!")