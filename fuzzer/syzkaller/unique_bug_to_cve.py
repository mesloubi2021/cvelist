import json
import sqlite3
import sys


def main(argv):
  output = []
  conn = sqlite3.connect("mirror.sl3")
  cve_eligible_bugs = []
  with open(argv[0]) as f:
    o = json.load(f)
    all_bugs = {}
    for bug in o:
        # check if there's a dupe syzkaller report
        is_dupe = False
        dupe_has_cve = False
        has_cve = len(bug['cves']) > 0
        for id in bug['unique_ids']:
            if id in all_bugs:
                if has_cve and len(all_bugs[id]['cves']) > 0:
                    print("two CVEs share reference %s" % id)
                is_dupe = True

        if not is_dupe or has_cve:
            for id in bug['unique_ids']:
                if id not in all_bugs:
                    all_bugs[id] = bug
                else:
                    dupe_bug = all_bugs[id]
                    for id in dupe_bug['unique_ids']:
                        all_bugs[id] = bug
                        bug['unique_ids'] = list(
                            set(bug['unique_ids'] + dupe_bug['unique_ids']))

    unique_bugs = list(set([json.dumps(bug) for bug in all_bugs.values()]))
    unique_bugs.sort(reverse=True)

    for bug_serialized in unique_bugs:
        bug = json.loads(bug_serialized)
        # check if there's a dupe CVE
        unique_ids_q = ','.join('?'*len(bug["unique_ids"]))
        cur = conn.cursor()
        cur.execute("SELECT cve FROM cve WHERE `commit` IN (%s)" %
                    unique_ids_q, bug["unique_ids"])
        results = cur.fetchall()
        if len(results) == 0:
            cve_eligible_bugs.append(bug)
        else:
            for (cve,) in results:
                bug['cves'] = list(set(bug['cves'] + [cve]))

    CVEs = ["CVE-2022-0001", "CVE-2022-0002"]
    for cve_bug in cve_eligible_bugs:
        if not len(cve_bug['cves']):
            cve_num = CVEs.pop(0)
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

# we can get the reproducer from
# https://syzkaller.appspot.com/bug?id=00c573f2cdb88dadbf65549e1b8ca32344b18a96&json=1


if __name__ == "__main__":
   main(sys.argv[1:])
