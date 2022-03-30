import json
import re
import sqlite3

conn = sqlite3.connect("mirror.sl3")

with open("test/syzkaller-api-response-get-bugs.json") as f:
    o = json.load(f)
    for bug in o:
        commits_q = ','.join('?'*len(bug["commit_id"]))
        backports = []
        fixed_versions = []
        affected_versions = []
        cur = conn.cursor()
        cur.execute("SELECT reported_by FROM reported_by WHERE `commit` IN (%s)" %
                    commits_q, bug["commit_id"])
        reported_by_ids = []
        for (reported_by,) in cur.fetchall():
          syzkaller_id = re.match(
              r"syzbot[+]([0-9a-f]+)?@syzkaller[.]appspotmail[.]com", reported_by)
          if syzkaller_id:
            reported_by_ids.append(syzkaller_id.group(1))
        cur = conn.cursor()
        cur.execute("SELECT `commit` FROM upstream WHERE upstream IN (%s)" %
                    commits_q, bug["commit_id"])
        backports += [commit for (commit,) in cur.fetchall()]
        backports_q = ','.join(['?']*len(backports))
        cur = conn.cursor()
        cur.execute("SELECT tags FROM tags WHERE `commit` IN (%s) OR `commit` IN (%s)" % (
            commits_q, backports_q), bug["commit_id"] + backports)
        fixed_tags = []
        for (tag,) in cur.fetchall():
            fixed_tags.append(tag)
        fixed_versions = [
            re.match(r"(?:tags/(v[0-9.]*))?", tag).group(1) for tag in fixed_tags]
        cur = conn.cursor()
        cur.execute("SELECT fixes FROM fixes WHERE `commit` IN (%s)" %
                    commits_q, bug["commit_id"])
        short_fix_ids = []
        for (fixes,) in cur.fetchall():
            if " " in fixes:
                fixes_parts = fixes.split(" ", 1)
                short_fix_ids.append(fixes_parts[0])
        short_fix_ids_q = ",".join(["(?)"]*len(short_fix_ids))
        if len(short_fix_ids):
            cur = conn.cursor()
            cur.execute("SELECT tags, `commit` FROM tags JOIN (select * from (select 0 short_commit union values %s) limit -1 offset 1) sfi ON (tags.`commit`>=sfi.short_commit AND tags.`commit`<=sfi.short_commit||'g')" % short_fix_ids_q, short_fix_ids)
            vuln_tags = []
            vuln_commits = []
            for (tag, commit) in cur.fetchall():
                vuln_tags.append(tag)
                vuln_commits.append(commit)
            vuln_commits_q = ",".join(["(?)"*len(vuln_commits)])
            cur = conn.cursor()
            cur.execute("SELECT tags FROM tags WHERE `commit` IN (SELECT `commit` FROM upstream WHERE upstream IN (%s))" %
                        vuln_commits_q, vuln_commits)
            for (tag,) in cur.fetchall():
                vuln_tags.append(tag)
            affected_versions = [
                re.match(r"(?:tags/(v[0-9.]*))?", tag).group(1) for tag in vuln_tags]
        subsystems = []
        solutions = []
        for title in bug["commits"]:
            if ":" in title:
                parts = title.split(":", 1)
                if "," in parts[0]:
                    subparts = parts[0].split(",")
                    for subpart in subparts:
                        subsystems.append(subpart.strip())
                else:
                    subsystems.append(parts[0])
                solutions.append(parts[1].strip())
        if len(subsystems) == 0:
            subsystem = ""
        elif len(subsystems) == 1:
            subsystem = " " + subsystems[0] + " subsystem"
        else:
            subsystem = " " + ", ".join(subsystems) + " subsystems"

        problems = []
        for title in bug["titles"]:
            if ":" in title:
                parts = title.split(":", 1)
                if parts[0] == "KASAN":
                    problems.append(parts[1].strip())
        if len(problems) == 0:
            description = "a security problem resolved by " + \
                ",".join(solutions).lower()
        elif len(problems) == 1:
            description = "a " + problems[0].lower()
        else:
            description = ", ".join(problems)

        unique_bug = {
            "unique_ids":
            list(set([bug['report_id']] + bug['report_ext_id'] +
                     bug['commit_id'] + backports)),
            "summary": "Vulnerability in the Linux Kernel%s caused %s" % (
                subsystem, description),
            "references":
            bug['report_link'] +
            ["https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=" + cid
             for cid in bug['commit_id']
             ] +
            ["http://syzkaller.appspot.com/bug?id=" + bug['report_id']],
            "versions": {
                "fixed": fixed_versions,
                "affected": affected_versions
            }
        }
        print(unique_bug)
