#!/usr/bin/env python3
"""
Convert secagent JSON output to SARIF format for GitHub Security tab.
Usage: python3 json-to-sarif.py secagent-results.json results.sarif
"""

import json
import sys
from datetime import datetime

def convert_to_sarif(input_file, output_file):
    with open(input_file) as f:
        data = json.load(f)
    
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "secagent",
                    "informationUri": "https://github.com/secagent/secagent",
                    "rules": [],
                    "version": "0.3.0"
                }
            },
            "results": [],
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.utcnow().isoformat() + "Z"
            }]
        }]
    }
    
    # Track unique rules
    rules_seen = {}
    
    for finding in data.get("findings", []):
        # Create rule ID from scanner + type
        rule_id = f"{finding['scanner']}/{finding['type']}"
        
        # Add rule if not seen
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": finding.get("scanner", "unknown").title() + " - " + finding.get("type", "unknown").title(),
                "shortDescription": {
                    "text": finding.get("title", "Security finding")[:100]
                },
                "helpUri": finding.get("references", [None])[0] if finding.get("references") else None,
                "defaultConfiguration": {
                    "level": severity_to_level(finding.get("severity", "medium"))
                }
            }
        
        # Create SARIF result
        result = {
            "ruleId": rule_id,
            "level": severity_to_level(finding.get("severity", "medium")),
            "message": {
                "text": finding.get("description", finding.get("title", "Security issue detected"))
            },
            "locations": []
        }
        
        # Add location if available
        location = finding.get("location", {})
        if location.get("file"):
            result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": location["file"]
                    },
                    "region": {
                        "startLine": location.get("line", 1)
                    }
                }
            })
        
        # Add CVE/CWE if available
        if finding.get("cve"):
            result["message"]["text"] += f" (CVE: {finding['cve']})"
        
        sarif["runs"][0]["results"].append(result)
    
    # Add rules to driver
    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_seen.values())
    
    # Write output
    with open(output_file, 'w') as f:
        json.dump(sarif, f, indent=2)
    
    print(f"Converted {len(data.get('findings', []))} findings to SARIF")
    print(f"Output: {output_file}")

def severity_to_level(severity):
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note"
    }
    return mapping.get(severity.lower() if severity else "medium", "warning")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 json-to-sarif.py <input.json> <output.sarif>")
        sys.exit(1)
    
    convert_to_sarif(sys.argv[1], sys.argv[2])
