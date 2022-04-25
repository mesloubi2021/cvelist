import json
import sqlite3
import sys


def main(argv):
    cve_eligible_bugs = []
    conn = sqlite3.connect("mirror.sl3")
    with open(argv[0]) as base_file, open(argv[1]) as delta_file, open(argv[2]) as cves_file:
        CVEs = json.load(cves_file)
        base = json.load(base_file)
        delta = json.load(delta_file)
        all_bugs = {}
        for bug in base+delta:
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
                            bug['unique_ids'].sort()

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

        for cve_bug in cve_eligible_bugs:
            if not len(cve_bug['cves']):
                cve_num = CVEs.pop(0)
                if not cve_num:
                    raise Exception("No CVEs left, :(")
                cve_bug['cves'].append(cve_num)

    cve_eligible_bugs.sort(key=json.dumps)
    print(json.dumps(cve_eligible_bugs))

# we can get the reproducer from
# https://syzkaller.appspot.com/bug?id=00c573f2cdb88dadbf65549e1b8ca32344b18a96&json=1


if __name__ == "__main__":
    main(sys.argv[1:])
