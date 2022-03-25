import json
import sqlite3

conn = sqlite3.connect("mirror.sl3")

with open("test/syzkaller-api-response-get-bugs.json") as f:
  o = json.load(f)
  for bug in o:
    commits_q = ','.join('?'*len(bug["commit_id"]))
    #print(bug)
    backports = []
    fixed_versions = []
    affected_versions = []
    cur = conn.cursor()
    cur.execute("SELECT `commit` FROM upstream WHERE upstream IN (%s)"%commits_q, bug["commit_id"])
    backports += [commit for (commit,) in cur.fetchall()]
    cur = conn.cursor()
    cur.execute("SELECT fixes FROM fixes WHERE `commit` IN (%s)"%commits_q, bug["commit_id"])
    short_fix_ids = []
    for (fixes,) in cur.fetchall():
      if " " in fixes:
        fixes_parts = fixes.split(" ", 1)
        short_fix_ids.append(fixes_parts[0])
    print(short_fix_ids)

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
      description = "a security problem resolved by " + ",".join(solutions).lower()
    elif len(problems) == 1:
      description = "a " + problems[0].lower()
    else:
      description = ", ".join(problems)

    unique_bug = {
      "unique_ids":
        [bug['report_id']] + bug['report_ext_id'] + bug['commit_id'] + backports,
      "summary": "Vulnerability in the Linux Kernel%s caused %s"%(
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

