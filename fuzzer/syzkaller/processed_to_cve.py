import sys
import json


def main(argv):
  output = []
  CVEs = ["CVE-2022-0001", "CVE-2022-0002"]
  with open(argv[0]) as f:
      o = json.load(f)
      for cve_bug in o:
          if len(cve_bug['cves']) == 1:
              cve_num = cve_bug['cves'][0]
              # TODO: check if the cve belongs to us and is pending publication
              if not cve_num:
                  raise Exception("No CVEs left, :(")
              cve_record = {
                  "dataType": "CVE_RECORD",
                  "dataVersion": "5.0",
                  "cveMetadata": {
                      "cveId": cve_num,
                      "assignerOrgId": "923d8096-d055-4df2-b6f9-17416a335a76",
                      "state": "PUBLISHED"
                  },
                  "containers": {
                      "cna": {
                          "providerMetadata": {
                              "orgId": "923d8096-d055-4df2-b6f9-17416a335a76"
                          },
                          "problemTypes": [
                              {
                                  "descriptions": [
                                      {
                                          "lang": "en",
                                          "description": "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
                                          "cweId": "CWE-119",
                                          "type": "CWE"
                                      }
                                  ]
                              }
                          ],
                          "affected": [
                              {
                                  "vendor": "Linux",
                                  "product": "Linux Kernel",
                                  "versions": [
                                      {
                                          "version": "0",
                                          "versionType": "semver",
                                          "lessThan": "*",
                                          "status": ("unaffected" if cve_bug["versions"]["affected"] else "affected"),
                                          "changes": [
                                              {"at": version,
                                               "status": "affected"}
                                              for version in cve_bug["versions"]["affected"]
                                          ] + [
                                              {"at": version,
                                               "status": "unaffected"}
                                              for version in cve_bug["versions"]["fixed"]]
                                      }
                                  ],
                                  "defaultStatus": "unaffected"
                              }
                          ],
                          "descriptions": [
                              {
                                  "lang": "en",
                                  "value": cve_bug["summary"]
                              }
                          ],
                          "references": [{"url": ref} for ref in cve_bug["references"]],
                          "credits": [
                              {
                                  "lang": "en",
                                  "value": "Syzkaller",
                                  "type": "tool"
                              }
                          ]
                      }
                  }
              }
              output.append(cve_record)
  print(json.dumps(output))


if __name__ == "__main__":
    main(sys.argv[1:])
