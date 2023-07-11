#!/usr/bin/python3

import google.auth
from google.auth.transport.requests import AuthorizedSession

import json
import requests
import sys

def query_llm_prompts(authed_session, prompts):
    response = authed_session.post(
        'https://us-central1-aiplatform.googleapis.com/v1/projects/sdcpocs/locations/us-central1/publishers/google/models/text-bison:predict',
        json={
            "instances": [{"prompt": prompt["prompt"]} for prompt in prompts],
            "parameters": {
                "temperature": 0,
                "maxOutputTokens": 256,
                "topK": 1,
                "topP": 0.0
            }
        })
    print(response.content, file=sys.stderr)
    predictions = json.loads(response.content)["predictions"]
    return [prediction["content"] + prompts[idx]["trailer"] if "content" in prediction else prompts[idx]["fallback"] for idx, prediction in enumerate(predictions)]


def write_short_summary_prompt(commits, crashes, upstream_fix, fixed_tags, vuln_tags, msgs):
    prompt = """Provide a summary following the template:
```
The [COMPONENT] in the Linux kernel has a [PROBLEMTYPE] vulnerability. This vulnerability could be exploited by an attacker to cause memory corruption when [ROOTCAUSE].
```

Variables:
- PROBLEMTYPE: What vulnerability was fixed? (summarize what the memory corruption vulnerability that was fixed based on the patch commit message)
- COMPONENT: In which subsystem was the bug? (extract this information from the commit title, affected files and reproducer)
- ROOTCAUSE: What was the cause for the vulnerability? (summarize the mistake in code fixed by the commit message)

EXAMPLE: CRASH: ["", "KASAN: global-out-of-bounds Read in crypto_chacha20_crypt"] COMMITS: ["crypto: skcipher - set walk.iv for zero-length inputs"] DESCRIPTION: ["crypto: skcipher - set walk.iv for zero-length inputs\n\nAll the ChaCha20 algorithms as well as the ARM bit-sliced AES-XTS\nalgorithms call skcipher_walk_virt(), then access the IV (walk.iv)\nbefore checking whether any bytes need to be processed (walk.nbytes).\n\nBut if the input is empty, then skcipher_walk_virt() doesn't set the IV,\nand the algorithms crash trying to use the uninitialized IV pointer.\n\nFix it by setting the IV earlier in skcipher_walk_virt().  Also fix it\nfor the AEAD walk functions.\n\nThis isn't a perfect solution because we can't actually align the IV to\n->cra_alignmask unless there are bytes to process, for one because the\ntemporary buffer for the aligned IV is freed by skcipher_walk_done(),\nwhich is only called when there are bytes to process.  Thus, algorithms\nthat require aligned IVs will still need to avoid accessing the IV when\nwalk.nbytes == 0.  Still, many algorithms/architectures are fine with\nIVs having any alignment, and even for those that aren't, a misaligned\npointer bug is much less severe than an uninitialized pointer bug.\n\nThis change also matches the behavior of the older blkcipher_walk API.\n\nFixes: 0cabf2af6f5a (\"crypto: skcipher - Fix crash on zero-length input\")\nReported-by: syzbot <syzkaller@googlegroups.com>\nCc: <stable@vger.kernel.org> # v4.14+\nSigned-off-by: Eric Biggers <ebiggers@google.com>\nSigned-off-by: Herbert Xu <herbert@gondor.apana.org.au>\n"]
ANSWER: The crypto subsystem of the Linux kernel has an out of bounds vulnerability. The vulnerability could be exploited by an attacker to cause memory corruption when crypto algorithm implementations like ChaCha20 and ARM's bit-sliced AES-XTS read an uninitialized IV pointer when the input is empty.

EXAMPLE: CRASH: ["", "KASAN: use-after-free Read in sock_def_write_space"] COMMITS: ["llc: make sure applications use ARPHRD_ETHER"] DESCRIPTION: ["llc: make sure applications use ARPHRD_ETHER\n\nsyzbot was to trigger a bug by tricking AF_LLC with\nnon sensible addr->sllc_arphrd\n\nIt seems clear LLC requires an Ethernet device.\n\nBack in commit abf9d537fea2 (\"llc: add support for SO_BINDTODEVICE\")\nOctavian Purdila added possibility for application to use a zero\nvalue for sllc_arphrd, convert it to ARPHRD_ETHER to not cause\nregressions on existing applications.\n\nBUG: KASAN: use-after-free in __read_once_size include/linux/compiler.h:199 [inline]\nBUG: KASAN: use-after-free in list_empty include/linux/list.h:268 [inline]\nBUG: KASAN: use-after-free in waitqueue_active include/linux/wait.h:126 [inline]\nBUG: KASAN: use-after-free in wq_has_sleeper include/linux/wait.h:160 [inline]\nBUG: KASAN: use-after-free in skwq_has_sleeper include/net/sock.h:2092 [inline]\nBUG: KASAN: use-after-free in sock_def_write_space+0x642/0x670 net/core/sock.c:2813\nRead of size 8 at addr ffff88801e0b4078 by task ksoftirqd/3/27\n\nCPU: 3 PID: 27 Comm: ksoftirqd/3 Not tainted 5.5.0-rc1-syzkaller #0\nHardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014\nCall Trace:\n __dump_stack lib/dump_stack.c:77 [inline]\n dump_stack+0x197/0x210 lib/dump_stack.c:118\n print_address_description.constprop.0.cold+0xd4/0x30b mm/kasan/report.c:374\n __kasan_report.cold+0x1b/0x41 mm/kasan/report.c:506\n kasan_report+0x12/0x20 mm/kasan/common.c:639\n __asan_report_load8_noabort+0x14/0x20 mm/kasan/generic_report.c:135\n __read_once_size include/linux/compiler.h:199 [inline]\n list_empty include/linux/list.h:268 [inline]\n waitqueue_active include/linux/wait.h:126 [inline]\n wq_has_sleeper include/linux/wait.h:160 [inline]\n skwq_has_sleeper include/net/sock.h:2092 [inline]\n sock_def_write_space+0x642/0x670 net/core/sock.c:2813\n sock_wfree+0x1e1/0x260 net/core/sock.c:1958\n skb_release_head_state+0xeb/0x260 net/core/skbuff.c:652\n skb_release_all+0x16/0x60 net/core/skbuff.c:663\n __kfree_skb net/core/skbuff.c:679 [inline]\n consume_skb net/core/skbuff.c:838 [inline]\n consume_skb+0xfb/0x410 net/core/skbuff.c:832\n __dev_kfree_skb_any+0xa4/0xd0 net/core/dev.c:2967\n dev_kfree_skb_any include/linux/netdevice.h:3650 [inline]\n e1000_unmap_and_free_tx_resource.isra.0+0x21b/0x3a0 drivers/net/ethernet/intel/e1000/e1000_main.c:1963\n e1000_clean_tx_irq drivers/net/ethernet/intel/e1000/e1000_main.c:3854 [inline]\n e1000_clean+0x4cc/0x1d10 drivers/net/ethernet/intel/e1000/e1000_main.c:3796\n napi_poll net/core/dev.c:6532 [inline]\n net_rx_action+0x508/0x1120 net/core/dev.c:6600\n __do_softirq+0x262/0x98c kernel/softirq.c:292\n run_ksoftirqd kernel/softirq.c:603 [inline]\n run_ksoftirqd+0x8e/0x110 kernel/softirq.c:595\n smpboot_thread_fn+0x6a3/0xa40 kernel/smpboot.c:165\n kthread+0x361/0x430 kernel/kthread.c:255\n ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352\n\nAllocated by task 8247:\n save_stack+0x23/0x90 mm/kasan/common.c:72\n set_track mm/kasan/common.c:80 [inline]\n __kasan_kmalloc mm/kasan/common.c:513 [inline]\n __kasan_kmalloc.constprop.0+0xcf/0xe0 mm/kasan/common.c:486\n kasan_slab_alloc+0xf/0x20 mm/kasan/common.c:521\n slab_post_alloc_hook mm/slab.h:584 [inline]\n slab_alloc mm/slab.c:3320 [inline]\n kmem_cache_alloc+0x121/0x710 mm/slab.c:3484\n sock_alloc_inode+0x1c/0x1d0 net/socket.c:240\n alloc_inode+0x68/0x1e0 fs/inode.c:230\n new_inode_pseudo+0x19/0xf0 fs/inode.c:919\n sock_alloc+0x41/0x270 net/socket.c:560\n __sock_create+0xc2/0x730 net/socket.c:1384\n sock_create net/socket.c:1471 [inline]\n __sys_socket+0x103/0x220 net/socket.c:1513\n __do_sys_socket net/socket.c:1522 [inline]\n __se_sys_socket net/socket.c:1520 [inline]\n __ia32_sys_socket+0x73/0xb0 net/socket.c:1520\n do_syscall_32_irqs_on arch/x86/entry/common.c:337 [inline]\n do_fast_syscall_32+0x27b/0xe16 arch/x86/entry/common.c:408\n entry_SYSENTER_compat+0x70/0x7f arch/x86/entry/entry_64_compat.S:139\n\nFreed by task 17:\n save_stack+0x23/0x90 mm/kasan/common.c:72\n set_track mm/kasan/common.c:80 [inline]\n kasan_set_free_info mm/kasan/common.c:335 [inline]\n __kasan_slab_free+0x102/0x150 mm/kasan/common.c:474\n kasan_slab_free+0xe/0x10 mm/kasan/common.c:483\n __cache_free mm/slab.c:3426 [inline]\n kmem_cache_free+0x86/0x320 mm/slab.c:3694\n sock_free_inode+0x20/0x30 net/socket.c:261\n i_callback+0x44/0x80 fs/inode.c:219\n __rcu_reclaim kernel/rcu/rcu.h:222 [inline]\n rcu_do_batch kernel/rcu/tree.c:2183 [inline]\n rcu_core+0x570/0x1540 kernel/rcu/tree.c:2408\n rcu_core_si+0x9/0x10 kernel/rcu/tree.c:2417\n __do_softirq+0x262/0x98c kernel/softirq.c:292\n\nThe buggy address belongs to the object at ffff88801e0b4000\n which belongs to the cache sock_inode_cache of size 1152\nThe buggy address is located 120 bytes inside of\n 1152-byte region [ffff88801e0b4000, ffff88801e0b4480)\nThe buggy address belongs to the page:\npage:ffffea0000782d00 refcount:1 mapcount:0 mapping:ffff88807aa59c40 index:0xffff88801e0b4ffd\nraw: 00fffe0000000200 ffffea00008e6c88 ffffea0000782d48 ffff88807aa59c40\nraw: ffff88801e0b4ffd ffff88801e0b4000 0000000100000003 0000000000000000\npage dumped because: kasan: bad access detected\n\nMemory state around the buggy address:\n ffff88801e0b3f00: fb fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc\n ffff88801e0b3f80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc\n>ffff88801e0b4000: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb\n                                                                ^\n ffff88801e0b4080: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb\n ffff88801e0b4100: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb\n\nFixes: abf9d537fea2 (\"llc: add support for SO_BINDTODEVICE\")\nSigned-off-by: Eric Dumazet <edumazet@google.com>\nSigned-off-by: David S. Miller <davem@davemloft.net>\n"]
ANSWER: The llc subsystem of the Linux Kernel has a use after free vulnerability. The vulnerability could be exploited by an attacker to cause memory corruption when passing a zero value for sllc_arphrd while LLC expected an ethernet device.

EXAMPLE: CRASH: ["", "KASAN: use-after-free Read in mcba_usb_disconnect"] COMMITS: ["can: mcba_usb: fix use-after-free on disconnect"] DESCRIPTION: ["can: mcba_usb: fix use-after-free on disconnect\n\nThe driver was accessing its driver data after having freed it.\n\nFixes: 51f3baad7de9 (\"can: mcba_usb: Add support for Microchip CAN BUS Analyzer\")\nCc: stable <stable@vger.kernel.org>     # 4.12\nCc: Remigiusz Ko\u0142\u0142\u0105taj <remigiusz.kollataj@mobica.com>\nReported-by: syzbot+e29b17e5042bbc56fae9@syzkaller.appspotmail.com\nSigned-off-by: Johan Hovold <johan@kernel.org>\nSigned-off-by: Marc Kleine-Budde <mkl@pengutronix.de>\n"]
ANSWER: The can/mcba_usb subsystem of the Linux kernel has a use after free vulnerability. The vulnerability could be exploited by an attacker to cause memory corruption when the driver accessed data after having it freed while disconnecting.

EXAMPLE: CRASH: ["KASAN: use-after-free Read in bdev_evict_inode"] COMMITS: ["block: ensure the bdi is freed after inode_detach_wb"] DESCRIPTION: ["block: ensure the bdi is freed after inode_detach_wb\n\ninode_detach_wb references the \"main\" bdi of the inode.  With the\nrecent change to move the bdi from the request_queue to the gendisk\nthis causes a guaranteed use after free when using certain cgroup\nconfigurations.  The big itself is older through as any non-default\ninode reference (e.g. an open file descriptor) could have injected\nthis use after free even before that.\n\nFixes: 52ebea749aae (\"writeback: make backing_dev_info host cgroup-specific bdi_writebacks\")\nReported-by: Qian Cai <quic_qiancai@quicinc.com>\nReported-by: syzbot <syzbot+1fb38bb7d3ce0fa3e1c4@syzkaller.appspotmail.com>\nSigned-off-by: Christoph Hellwig <hch@lst.de>\nLink: https://lore.kernel.org/r/20210816122614.601358-3-hch@lst.de\nSigned-off-by: Jens Axboe <axboe@kernel.dk>\n"]
ANSWER: The block subsystem of the Linux Kernel has a use after free vulnerability. The vulnerability could be exploited by an attacker to cause memory corruption when using certain cgroup configurations because the bdi of the inode wasn't always freed after inode_detach_wb.

EXAMPLE: CRASH: ["", "KASAN: use-after-free Read in sock_def_write_space (2)"] COMMITS: ["qrtr: orphan socket in qrtr_release()"] DESCRIPTION: ["qrtr: orphan socket in qrtr_release()\n\nWe have to detach sock from socket in qrtr_release(),\notherwise skb->sk may still reference to this socket\nwhen the skb is released in tun->queue, particularly\nsk->sk_wq still points to &sock->wq, which leads to\na UAF.\n\nReported-and-tested-by: syzbot+6720d64f31c081c2f708@syzkaller.appspotmail.com\nFixes: 28fb4e59a47d (\"net: qrtr: Expose tunneling endpoint to user space\")\nCc: Bjorn Andersson <bjorn.andersson@linaro.org>\nCc: Eric Dumazet <eric.dumazet@gmail.com>\nSigned-off-by: Cong Wang <xiyou.wangcong@gmail.com>\nReviewed-by: Eric Dumazet <edumazet@google.com>\nSigned-off-by: David S. Miller <davem@davemloft.net>\n"]
ANSWER: The qrtr subsystem of the Linux kernel has a use after free vulnerability. The vulnerability could be exploited by an attacker to cause memory corruption when the socket was not properly detached from the qrtr, as otherwise skb->sk may still reference the socket when skb is released in tun->queue.

EXAMPLE: CRASH: %s COMMITS: %s DESCRIPTION: %s
ANSWER:""" % (json.dumps(list(crashes)), json.dumps(list(commits)), json.dumps(msgs))
    fix_trailer = " This vulnerability exists in all versions of the Linux Kernel from %s until commit %s (%s)." % (
        ', '.join(vuln_tags), ', '.join(upstream_fix), ', '.join(fixed_tags)
    )
    return {
        "prompt": prompt,
        "fallback": ", ".join(list(commits)),
        "trailer": fix_trailer
    }

def write_long_description_prompt(msgs):
    prompt = """You are a vulnerability description generator.

I have a Linux kernel commit that fixes a potential security vulnerability.
Quickly explain in technical terms the possible vulnerability being fixed by this commit and the possible security impact.
Briefly explain the vulnerability type and how it usually is exploited.
Respond with "The patch commit for this vulnerability fixes ..." with the description of the fix and the potential vulnerability.
Follow with "Vulnerabilities of type ... are exploited by ..." and a brief description of that vulnerability type and how to exploit them.
End with "The security impact of this vulnerability could be ..." and a reason explaining the worst case scenario that a potential vulnerability like this could have and the most likely case.
The last sentence of the output should be "To resolve this vulnerability patch the kernel past the fix commit."

Expand all acronyms so someone that doesn't know the code can understand it.
Purpose is to explain the vulnerability so no subjective opinions only facts.
Mention that this vulnerability has a confirmed proof of concept code and the vendor has provided an official fix.

Keep the response below 200 words.

---
```
%s
```""" % ("```\n```".join(msgs))
    return {
        "prompt": prompt,
        "fallback": "\n\n".join(list(msgs)),
        "trailer": "\n\nThis description was automatically generated based on the commit message."
    }

def main(argv):
    creds, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    authed_session = AuthorizedSession(creds)

    bugs = []
    if len(argv) < 1:
        raise Exception("No input file")

    with open(argv[0]) as delta_file:
        delta_bugs = json.load(delta_file)
        for bug in delta_bugs:
            msgs = []
            for commit in bug['summary_inputs']['fixed_by_upstream']:
                response = requests.get("https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux-stable/+/%s?format=json" % commit)
                try:
                    msgs.append(json.loads(response.content[5:])['message'][0:2000])
                except json.decoder.JSONDecodeError:
                    pass
            bug["summary"] = query_llm_prompts(authed_session, [write_short_summary_prompt(
                bug['summary_inputs']['commits'],
                bug['summary_inputs']['crashes'],
                bug['summary_inputs']['fixed_by_upstream'],
                bug['summary_inputs']['fixed_by_tag'],
                bug['summary_inputs']['introduced_by_tag'],
                msgs)])
            bug["description"] = query_llm_prompts(authed_session, [write_long_description_prompt(msgs)])
            bugs.append(bug)

    print(json.dumps(bugs))

if __name__ == "__main__":
   main(sys.argv[1:])
