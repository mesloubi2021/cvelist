import json
import sqlite3

conn = sqlite3.connect("mirror.sl3")

cve_eligible_bugs = []

with open("test/syzkaller-two-cves-unique-bugs.json") as f:
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

    unique_bugs = set([json.dumps(bug) for bug in all_bugs.values()])

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

    for cve_bug in cve_eligible_bugs:
        if not len(cve_bug['cves']):
            print("reserving cve for %s" % cve_bug)

# we can get the reproducer from
# https://syzkaller.appspot.com/bug?id=00c573f2cdb88dadbf65549e1b8ca32344b18a96&json=1
