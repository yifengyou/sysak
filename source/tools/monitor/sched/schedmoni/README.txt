1 run the nosched
 $ sudo ./out/sysak nosched	#default threshold 10ms
 or
 $ sudo ./out/sysak nosched -t 1  #set the threshold to 1ms

The out looks like:
sudo ./out/sysak nosched -t 1
Threshold set to 1 ms
libbpf: loading object 'nosched_bpf' from buffer
.....  (#a lot of messages)
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
Running....
 tips:Ctl+c show the result!

2 get the result
2.1 use trace_pipe(Optional， for debug)
 $ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-110777 [014] dNh. 19777.314467: 0: cc1 :lat is 1001 us, 1 ticks
           <...>-110849 [016] dNh. 19777.556471: 0: cc1 :lat is 1000 us, 1 ticks
           <...>-110712 [000] dNh. 19777.932467: 0: cc1 :lat is 1005 us, 1 ticks
2.2 stop the process and get the result
We enter the "Ctl+c" to stop the process, the result looks as follows:
Running....
 tips:Ctl+c show the result!
^C
***********************************
cc1<116321> [19795.442018507]: lat=4000us, lat_tick=4
<ffffffff9aa0191f> apic_timer_interrupt
<ffffffff9a81a7d1> __lock_text_start
<ffffffff9a1f0bc8> release_pages
<ffffffff9a21c576> tlb_flush_mmu_free
<ffffffff9a21c6c2> arch_tlb_finish_mmu
<ffffffff9a21c83f> tlb_finish_mmu
<ffffffff9a227edd> exit_mmap
<ffffffff9a08e604> mmput
<ffffffff9a098227> do_exit
<ffffffff9a098c9a> do_group_exit
<ffffffff9a0a53e5> get_signal
<ffffffff9a01ed46> do_signal
<ffffffff9a0021c5> exit_to_usermode_loop
<ffffffff9a002614> prepare_exit_to_usermode
<ffffffff9aa00a34> swapgs_restore_regs_and_return_to_usermode
----------------------
cc1<111581> [19775.265934964]: lat=1005us, lat_tick=1
<ffffffff9aa0191f> apic_timer_interrupt
<ffffffff9a1e533d> free_unref_page_list
<ffffffff9a1f0bf7> release_pages
<ffffffff9a21c576> tlb_flush_mmu_free
<ffffffff9a21c6c2> arch_tlb_finish_mmu
<ffffffff9a21c83f> tlb_finish_mmu
<ffffffff9a227edd> exit_mmap
<ffffffff9a08e604> mmput
<ffffffff9a098227> do_exit
<ffffffff9a098c9a> do_group_exit
<ffffffff9a098d14> __x64_sys_exit_group
<ffffffff9a0027eb> do_syscall_64
<ffffffff9aa00088> entry_SYSCALL_64_after_hwframe
..........(#a lot of messages)

3 the results
3.1 headers
 comm&pid       timestamp    latency(us)   latency(tick)
    |               |            |             |
cc1<111581> [19775.265934964]: lat=1005us, lat_tick=1

comm&pid: The name(or comm) and pid of the task which with need_to_resched flag but didn't schedle() for threshold time.
timestamp: The timestamp when no_sched happened.
latency(us): How many us the task with need_to_resched flag has no schedule().
latency(tick): Likes latency, but takes ticks as count.

3.2 stack
The stack back-trace of the current(the murderer) context.
<ffffffff9aa0191f> apic_timer_interrupt
<ffffffff9a1e533d> free_unref_page_list
<ffffffff9a1f0bf7> release_pages
<ffffffff9a21c576> tlb_flush_mmu_free
......
