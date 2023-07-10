#!/usr/bin/python3

import google.auth
import google.auth.transport.requests

import json
import requests
import sys

def summarize(token, commits, crashes):
    if False:
        prompt = """Provide a summary following the template:
    ```
    [PROBLEMTYPE] in [COMPONENT] causes [IMPACT].
    ```

    Variables:
    - PROBLEMTYPE: What root cause was fixed? (summarize what the memory corruption vulnerability that was fixed based on the patch commit message)
    - IMPACT: What was the consequence? (explain what the crash title shows and what type of memory corruption happened)
    - COMPONENT: In which subsystem was the bug? (extract this information from the commit title, affected files and reproducer)

    EXAMPLE: CRASH: ["KASAN: slab-out-of-bounds Read in ntfs_listxattr"] COMMITS: ["ntfs: Fix panic about slab-out-of-bounds caused by ntfs_listxattr()"]
    ANSWER: Slab out of bounds vulnerability on the ntfs subsystem caused by the function ntfs_listxattr.

    EXAMPLE: CRASH: ["KASAN: use-after-free Read in __vma_adjust"] COMMITS: ["fix vma iteration in mas_for_each() loop"]
    ANSWER: Use-after-free vulnerability on the mas_for_each function caused memory corruption.

    EXAMPLE: CRASH: ["KASAN: null-ptr-deref Write in get_block (2)"] COMMITS: ["fs/sysv: Null check to prevent null-ptr-deref bug"]
    ANSWER: Null pointer dereference in the fs/sysv subsystem of the Linux Kernel could be used to cause memory corruption.

    EXAMPLE: CRASH: ["KASAN: slab-use-after-free Read in f2fs_truncate_data_blocks_range"] COMMITS: ["f2fs: fix to do sanity check on direct node in truncate_dnode()"]
    ANSWER: Use after free vulnerability on the f2fs subsystem of the Linux Kernel on the truncate_dnode function causes potential memory corruption.

    EXAMPLE: CRASH: ["KASAN: use-after-free Read in hci_send_acl"] COMMITS: ["Bluetooth: verify AMP hci_chan before amp_destroy"]
    ANSWER: Use-after-free vulnerability in the bluetooth subsystem of the Linux Kernel on the hci_chan and amp_destroy functions could be used to cause memory corruption.

    EXAMPLE: CRASH: %s COMMITS: %s
    ANSWER:""" % (json.dumps(list(crashes)), json.dumps(list(commits)))
        response = requests.post(
            url="https://us-central1-aiplatform.googleapis.com/v1/projects/sdcpocs/locations/us-central1/publishers/google/models/text-bison:predict",
            headers={"authorization": "Bearer " + token},
            json={"instances": [
                {
                    "prompt": prompt
                }],
                "parameters": {
                    "temperature": 0,
                    "maxOutputTokens": 50,
                    "topK": 1,
                    "topP": 0.0
                }
            })
        print(
            (json.dumps(list(crashes)), json.dumps(list(commits))),
            json.loads(response.content)["predictions"][0]['content'],
            file=sys.stderr)
        return json.loads(response.content)["predictions"][0]['content']
    else:
        return "%s %s"%(";".join(commits), ";".join(crashes))

def main(argv):
    creds, project = google.auth.default()

    auth_req = google.auth.transport.requests.Request()
    creds.refresh(auth_req)

    bugs = []
    if len(argv) < 1:
        raise Exception("No input file")

    with open(argv[0]) as unique_file:
        unique_bugs = json.load(unique_file)
        for bug in unique_bugs:
            crashes = set()
            commits = set()
            repros = set()
            discussions = set()
            syzkaller_links = set()
            is_kasan = False
            for syzkaller in bug['syzkaller']:
                try:
                    with open("syzkaller/bug_%s.json"%syzkaller) as syzkaller_bug_file:
                        try:
                            syzkaller_bug = json.load(syzkaller_bug_file)
                            syzkaller_links.add("https://syzkaller.appspot.com/bug?%s" % syzkaller)
                            crashes.add(syzkaller_bug['title'])
                            if 'discussions' in syzkaller_bug:
                                for discussion in syzkaller_bug['discussions']:
                                    discussions.add(discussion)
                                    syzkaller_links.add(discussion)
                            if 'crashes' in syzkaller_bug:
                                for crash in syzkaller_bug['crashes']:
                                    if 'title' in crash:
                                        crashes.add(crash['title'])
                                    if 'syz-reproducer' in crash:
                                        repros.add(crash['syz-reproducer'])
                            if 'fix-commits' in syzkaller_bug:
                                for commit in syzkaller_bug['fix-commits']:
                                    if 'title' in commit and commit['title']:
                                        commits.add(commit['title'])
                                    if 'link' in commit and commit['link']:
                                        syzkaller_links.add(commit['link'])
                        except json.decoder.JSONDecodeError:
                            pass
                except FileNotFoundError:
                    pass
            if len(repros) > 0:
                for crash in crashes:
                    if 'KASAN' in crash:
                        is_kasan = True
                if not is_kasan:
                    continue
                bugs.append({
                    "cves": bug["cve"],
                    "osvs": [],
                    "unique_ids": bug['cve'] + bug['fixed_by'] + bug ['syzkaller'],
                    "summary": summarize(creds.token, commits, crashes),
                    "references": list(syzkaller_links),
                    "versions": {
                        "fixed": bug["fixed_by"],
                        "affected": bug["introduced_by"]
                    }
                })
    print(json.dumps(bugs))

if __name__ == "__main__":
   main(sys.argv[1:])
