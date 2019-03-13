#define __NR_restart_syscall          0
#define __NR_exit                     1
#define __NR_fork                     2
#define __NR_read                     3
#define __NR_write                    4
#define __NR_open                     5
#define __NR_close                    6
#define __NR_waitpid                  7
#define __NR_creat                    8
#define __NR_link                     9
#define __NR_unlink                  10
#define __NR_execve                  11
#define __NR_chdir                   12
#define __NR_time                    13
#define __NR_mknod                   14
#define __NR_chmod                   15
#define __NR_lchown                  16
#define __NR_break                   17
#define __NR_oldstat                 18
#define __NR_lseek                   19
#define __NR_getpid                  20
#define __NR_mount                   21
#define __NR_umount                  22
#define __NR_setuid                  23
#define __NR_getuid                  24
#define __NR_stime                   25
#define __NR_ptrace                  26
#define __NR_alarm                   27
#define __NR_oldfstat                28
#define __NR_pause                   29
#define __NR_utime                   30
#define __NR_stty                    31
#define __NR_gtty                    32
#define __NR_access                  33
#define __NR_nice                    34
#define __NR_ftime                   35
#define __NR_sync                    36
#define __NR_kill                    37
#define __NR_rename                  38
#define __NR_mkdir                   39
#define __NR_rmdir                   40
#define __NR_dup                     41
#define __NR_pipe                    42
#define __NR_times                   43
#define __NR_prof                    44
#define __NR_brk                     45
#define __NR_setgid                  46
#define __NR_getgid                  47
#define __NR_signal                  48
#define __NR_geteuid                 49
#define __NR_getegid                 50
#define __NR_acct                    51
#define __NR_umount2                 52
#define __NR_lock                    53
#define __NR_ioctl                   54
#define __NR_fcntl                   55
#define __NR_mpx                     56
#define __NR_setpgid                 57
#define __NR_ulimit                  58
#define __NR_oldolduname             59
#define __NR_umask                   60
#define __NR_chroot                  61
#define __NR_ustat                   62
#define __NR_dup2                    63
#define __NR_getppid                 64
#define __NR_getpgrp                 65
#define __NR_setsid                  66
#define __NR_sigaction               67
#define __NR_sgetmask                68
#define __NR_ssetmask                69
#define __NR_setreuid                70
#define __NR_setregid                71
#define __NR_sigsuspend              72
#define __NR_sigpending              73
#define __NR_sethostname             74
#define __NR_setrlimit               75
#define __NR_getrlimit               76
#define __NR_getrusage               77
#define __NR_gettimeofday            78
#define __NR_settimeofday            79
#define __NR_getgroups               80
#define __NR_setgroups               81
#define __NR_select                  82
#define __NR_symlink                 83
#define __NR_oldlstat                84
#define __NR_readlink                85
#define __NR_uselib                  86
#define __NR_swapon                  87
#define __NR_reboot                  88
#define __NR_readdir                 89
#define __NR_mmap                    90
#define __NR_munmap                  91
#define __NR_truncate                92
#define __NR_ftruncate               93
#define __NR_fchmod                  94
#define __NR_fchown                  95
#define __NR_getpriority             96
#define __NR_setpriority             97
#define __NR_profil                  98
#define __NR_statfs                  99
#define __NR_fstatfs                100
#define __NR_ioperm                 101
#define __NR_socketcall             102
#define __NR_syslog                 103
#define __NR_setitimer              104
#define __NR_getitimer              105
#define __NR_stat                   106
#define __NR_lstat                  107
#define __NR_fstat                  108
#define __NR_olduname               109
#define __NR_iopl                   110
#define __NR_vhangup                111
#define __NR_idle                   112
#define __NR_vm86                   113
#define __NR_wait4                  114
#define __NR_swapoff                115
#define __NR_sysinfo                116
#define __NR_ipc                    117
#define __NR_fsync                  118
#define __NR_sigreturn              119
#define __NR_clone                  120
#define __NR_setdomainname          121
#define __NR_uname                  122
#define __NR_modify_ldt             123
#define __NR_adjtimex               124
#define __NR_mprotect               125
#define __NR_sigprocmask            126
#define __NR_create_module          127
#define __NR_init_module            128
#define __NR_delete_module          129
#define __NR_get_kernel_syms        130
#define __NR_quotactl               131
#define __NR_getpgid                132
#define __NR_fchdir                 133
#define __NR_bdflush                134
#define __NR_sysfs                  135
#define __NR_personality            136
#define __NR_afs_syscall            137
#define __NR_setfsuid               138
#define __NR_setfsgid               139
#define __NR__llseek                140
#define __NR_getdents               141
#define __NR__newselect             142
#define __NR_flock                  143
#define __NR_msync                  144
#define __NR_readv                  145
#define __NR_writev                 146
#define __NR_getsid                 147
#define __NR_fdatasync              148
#define __NR__sysctl                149
#define __NR_mlock                  150
#define __NR_munlock                151
#define __NR_mlockall               152
#define __NR_munlockall             153
#define __NR_sched_setparam         154
#define __NR_sched_getparam         155
#define __NR_sched_setscheduler     156
#define __NR_sched_getscheduler     157
#define __NR_sched_yield            158
#define __NR_sched_get_priority_max 159
#define __NR_sched_get_priority_min 160
#define __NR_sched_rr_get_interval  161
#define __NR_nanosleep              162
#define __NR_mremap                 163
#define __NR_setresuid              164
#define __NR_getresuid              165
#define __NR_query_module           166
#define __NR_poll                   167
#define __NR_nfsservctl             168
#define __NR_setresgid              169
#define __NR_getresgid              170
#define __NR_prctl                  171
#define __NR_rt_sigreturn           172
#define __NR_rt_sigaction           173
#define __NR_rt_sigprocmask         174
#define __NR_rt_sigpending          175
#define __NR_rt_sigtimedwait        176
#define __NR_rt_sigqueueinfo        177
#define __NR_rt_sigsuspend          178
#define __NR_pread64                179
#define __NR_pwrite64               180
#define __NR_chown                  181
#define __NR_getcwd                 182
#define __NR_capget                 183
#define __NR_capset                 184
#define __NR_sigaltstack            185
#define __NR_sendfile               186
#define __NR_getpmsg                187
#define __NR_putpmsg                188
#define __NR_vfork                  189
#define __NR_ugetrlimit             190
#define __NR_readahead              191
#define __NR_pciconfig_read         198
#define __NR_pciconfig_write        199
#define __NR_pciconfig_iobase       200
#define __NR_multiplexer            201
#define __NR_getdents64             202
#define __NR_pivot_root             203
#define __NR_madvise                205
#define __NR_mincore                206
#define __NR_gettid                 207
#define __NR_tkill                  208
#define __NR_setxattr               209
#define __NR_lsetxattr              210
#define __NR_fsetxattr              211
#define __NR_getxattr               212
#define __NR_lgetxattr              213
#define __NR_fgetxattr              214
#define __NR_listxattr              215
#define __NR_llistxattr             216
#define __NR_flistxattr             217
#define __NR_removexattr            218
#define __NR_lremovexattr           219
#define __NR_fremovexattr           220
#define __NR_futex                  221
#define __NR_sched_setaffinity      222
#define __NR_sched_getaffinity      223
#define __NR_tuxcall                225
#define __NR_io_setup               227
#define __NR_io_destroy             228
#define __NR_io_getevents           229
#define __NR_io_submit              230
#define __NR_io_cancel              231
#define __NR_set_tid_address        232
#define __NR_fadvise64              233
#define __NR_exit_group             234
#define __NR_lookup_dcookie         235
#define __NR_epoll_create           236
#define __NR_epoll_ctl              237
#define __NR_epoll_wait             238
#define __NR_remap_file_pages       239
#define __NR_timer_create           240
#define __NR_timer_settime          241
#define __NR_timer_gettime          242
#define __NR_timer_getoverrun       243
#define __NR_timer_delete           244
#define __NR_clock_settime          245
#define __NR_clock_gettime          246
#define __NR_clock_getres           247
#define __NR_clock_nanosleep        248
#define __NR_swapcontext            249
#define __NR_tgkill                 250
#define __NR_utimes                 251
#define __NR_statfs64               252
#define __NR_fstatfs64              253
#define __NR_rtas                   255
#define __NR_sys_debug_setcontext   256
#define __NR_migrate_pages          258
#define __NR_mbind                  259
#define __NR_get_mempolicy          260
#define __NR_set_mempolicy          261
#define __NR_mq_open                262
#define __NR_mq_unlink              263
#define __NR_mq_timedsend           264
#define __NR_mq_timedreceive        265
#define __NR_mq_notify              266
#define __NR_mq_getsetattr          267
#define __NR_kexec_load             268
#define __NR_add_key                269
#define __NR_request_key            270
#define __NR_keyctl                 271
#define __NR_waitid                 272
#define __NR_ioprio_set             273
#define __NR_ioprio_get             274
#define __NR_inotify_init           275
#define __NR_inotify_add_watch      276
#define __NR_inotify_rm_watch       277
#define __NR_spu_run                278
#define __NR_spu_create             279
#define __NR_pselect6               280
#define __NR_ppoll                  281
#define __NR_unshare                282
#define __NR_splice                 283
#define __NR_tee                    284
#define __NR_vmsplice               285
#define __NR_openat                 286
#define __NR_mkdirat                287
#define __NR_mknodat                288
#define __NR_fchownat               289
#define __NR_futimesat              290
#define __NR_newfstatat             291
#define __NR_unlinkat               292
#define __NR_renameat               293
#define __NR_linkat                 294
#define __NR_symlinkat              295
#define __NR_readlinkat             296
#define __NR_fchmodat               297
#define __NR_faccessat              298
#define __NR_get_robust_list        299
#define __NR_set_robust_list        300
#define __NR_move_pages             301
#define __NR_getcpu                 302
#define __NR_epoll_pwait            303
#define __NR_utimensat              304
#define __NR_signalfd               305
#define __NR_timerfd_create         306
#define __NR_eventfd                307
#define __NR_sync_file_range2       308
#define __NR_fallocate              309
#define __NR_subpage_prot           310
#define __NR_timerfd_settime        311
#define __NR_timerfd_gettime        312
#define __NR_signalfd4              313
#define __NR_eventfd2               314
#define __NR_epoll_create1          315
#define __NR_dup3                   316
#define __NR_pipe2                  317
#define __NR_inotify_init1          318
#define __NR_perf_event_open        319
#define __NR_preadv                 320
#define __NR_pwritev                321
#define __NR_rt_tgsigqueueinfo      322
#define __NR_fanotify_init          323
#define __NR_fanotify_mark          324
#define __NR_prlimit64              325
#define __NR_socket                 326
#define __NR_bind                   327
#define __NR_connect                328
#define __NR_listen                 329
#define __NR_accept                 330
#define __NR_getsockname            331
#define __NR_getpeername            332
#define __NR_socketpair             333
#define __NR_send                   334
#define __NR_sendto                 335
#define __NR_recv                   336
#define __NR_recvfrom               337
#define __NR_shutdown               338
#define __NR_setsockopt             339
#define __NR_getsockopt             340
#define __NR_sendmsg                341
#define __NR_recvmsg                342
#define __NR_recvmmsg               343
#define __NR_accept4                344
#define __NR_name_to_handle_at      345
#define __NR_open_by_handle_at      346
#define __NR_clock_adjtime          347
#define __NR_syncfs                 348
#define __NR_sendmmsg               349
#define __NR_setns                  350
#define __NR_process_vm_readv       351
#define __NR_process_vm_writev      352
#define __NR_finit_module           353
#define __NR_kcmp                   354
#define __NR_sched_setattr          355
#define __NR_sched_getattr          356
#define __NR_renameat2              357
#define __NR_seccomp                358
#define __NR_getrandom              359
#define __NR_memfd_create           360
#define __NR_bpf                    361
#define __NR_execveat               362
#define __NR_switch_endian          363
#define __NR_userfaultfd            364
#define __NR_membarrier             365
#define __NR_mlock2                 378
#define __NR_copy_file_range        379
#define __NR_preadv2                380
#define __NR_pwritev2               381
#define __NR_kexec_file_load        382
#define __NR_statx                  383
#define __NR_pkey_alloc             384
#define __NR_pkey_free              385
#define __NR_pkey_mprotect          386
#define __NR_rseq                   387
#define __NR_io_pgetevents          388

#define SYS_restart_syscall          0
#define SYS_exit                     1
#define SYS_fork                     2
#define SYS_read                     3
#define SYS_write                    4
#define SYS_open                     5
#define SYS_close                    6
#define SYS_waitpid                  7
#define SYS_creat                    8
#define SYS_link                     9
#define SYS_unlink                  10
#define SYS_execve                  11
#define SYS_chdir                   12
#define SYS_time                    13
#define SYS_mknod                   14
#define SYS_chmod                   15
#define SYS_lchown                  16
#define SYS_break                   17
#define SYS_oldstat                 18
#define SYS_lseek                   19
#define SYS_getpid                  20
#define SYS_mount                   21
#define SYS_umount                  22
#define SYS_setuid                  23
#define SYS_getuid                  24
#define SYS_stime                   25
#define SYS_ptrace                  26
#define SYS_alarm                   27
#define SYS_oldfstat                28
#define SYS_pause                   29
#define SYS_utime                   30
#define SYS_stty                    31
#define SYS_gtty                    32
#define SYS_access                  33
#define SYS_nice                    34
#define SYS_ftime                   35
#define SYS_sync                    36
#define SYS_kill                    37
#define SYS_rename                  38
#define SYS_mkdir                   39
#define SYS_rmdir                   40
#define SYS_dup                     41
#define SYS_pipe                    42
#define SYS_times                   43
#define SYS_prof                    44
#define SYS_brk                     45
#define SYS_setgid                  46
#define SYS_getgid                  47
#define SYS_signal                  48
#define SYS_geteuid                 49
#define SYS_getegid                 50
#define SYS_acct                    51
#define SYS_umount2                 52
#define SYS_lock                    53
#define SYS_ioctl                   54
#define SYS_fcntl                   55
#define SYS_mpx                     56
#define SYS_setpgid                 57
#define SYS_ulimit                  58
#define SYS_oldolduname             59
#define SYS_umask                   60
#define SYS_chroot                  61
#define SYS_ustat                   62
#define SYS_dup2                    63
#define SYS_getppid                 64
#define SYS_getpgrp                 65
#define SYS_setsid                  66
#define SYS_sigaction               67
#define SYS_sgetmask                68
#define SYS_ssetmask                69
#define SYS_setreuid                70
#define SYS_setregid                71
#define SYS_sigsuspend              72
#define SYS_sigpending              73
#define SYS_sethostname             74
#define SYS_setrlimit               75
#define SYS_getrlimit               76
#define SYS_getrusage               77
#define SYS_gettimeofday            78
#define SYS_settimeofday            79
#define SYS_getgroups               80
#define SYS_setgroups               81
#define SYS_select                  82
#define SYS_symlink                 83
#define SYS_oldlstat                84
#define SYS_readlink                85
#define SYS_uselib                  86
#define SYS_swapon                  87
#define SYS_reboot                  88
#define SYS_readdir                 89
#define SYS_mmap                    90
#define SYS_munmap                  91
#define SYS_truncate                92
#define SYS_ftruncate               93
#define SYS_fchmod                  94
#define SYS_fchown                  95
#define SYS_getpriority             96
#define SYS_setpriority             97
#define SYS_profil                  98
#define SYS_statfs                  99
#define SYS_fstatfs                100
#define SYS_ioperm                 101
#define SYS_socketcall             102
#define SYS_syslog                 103
#define SYS_setitimer              104
#define SYS_getitimer              105
#define SYS_stat                   106
#define SYS_lstat                  107
#define SYS_fstat                  108
#define SYS_olduname               109
#define SYS_iopl                   110
#define SYS_vhangup                111
#define SYS_idle                   112
#define SYS_vm86                   113
#define SYS_wait4                  114
#define SYS_swapoff                115
#define SYS_sysinfo                116
#define SYS_ipc                    117
#define SYS_fsync                  118
#define SYS_sigreturn              119
#define SYS_clone                  120
#define SYS_setdomainname          121
#define SYS_uname                  122
#define SYS_modify_ldt             123
#define SYS_adjtimex               124
#define SYS_mprotect               125
#define SYS_sigprocmask            126
#define SYS_create_module          127
#define SYS_init_module            128
#define SYS_delete_module          129
#define SYS_get_kernel_syms        130
#define SYS_quotactl               131
#define SYS_getpgid                132
#define SYS_fchdir                 133
#define SYS_bdflush                134
#define SYS_sysfs                  135
#define SYS_personality            136
#define SYS_afs_syscall            137
#define SYS_setfsuid               138
#define SYS_setfsgid               139
#define SYS__llseek                140
#define SYS_getdents               141
#define SYS__newselect             142
#define SYS_flock                  143
#define SYS_msync                  144
#define SYS_readv                  145
#define SYS_writev                 146
#define SYS_getsid                 147
#define SYS_fdatasync              148
#define SYS__sysctl                149
#define SYS_mlock                  150
#define SYS_munlock                151
#define SYS_mlockall               152
#define SYS_munlockall             153
#define SYS_sched_setparam         154
#define SYS_sched_getparam         155
#define SYS_sched_setscheduler     156
#define SYS_sched_getscheduler     157
#define SYS_sched_yield            158
#define SYS_sched_get_priority_max 159
#define SYS_sched_get_priority_min 160
#define SYS_sched_rr_get_interval  161
#define SYS_nanosleep              162
#define SYS_mremap                 163
#define SYS_setresuid              164
#define SYS_getresuid              165
#define SYS_query_module           166
#define SYS_poll                   167
#define SYS_nfsservctl             168
#define SYS_setresgid              169
#define SYS_getresgid              170
#define SYS_prctl                  171
#define SYS_rt_sigreturn           172
#define SYS_rt_sigaction           173
#define SYS_rt_sigprocmask         174
#define SYS_rt_sigpending          175
#define SYS_rt_sigtimedwait        176
#define SYS_rt_sigqueueinfo        177
#define SYS_rt_sigsuspend          178
#define SYS_pread64                179
#define SYS_pwrite64               180
#define SYS_chown                  181
#define SYS_getcwd                 182
#define SYS_capget                 183
#define SYS_capset                 184
#define SYS_sigaltstack            185
#define SYS_sendfile               186
#define SYS_getpmsg                187
#define SYS_putpmsg                188
#define SYS_vfork                  189
#define SYS_ugetrlimit             190
#define SYS_readahead              191
#define SYS_pciconfig_read         198
#define SYS_pciconfig_write        199
#define SYS_pciconfig_iobase       200
#define SYS_multiplexer            201
#define SYS_getdents64             202
#define SYS_pivot_root             203
#define SYS_madvise                205
#define SYS_mincore                206
#define SYS_gettid                 207
#define SYS_tkill                  208
#define SYS_setxattr               209
#define SYS_lsetxattr              210
#define SYS_fsetxattr              211
#define SYS_getxattr               212
#define SYS_lgetxattr              213
#define SYS_fgetxattr              214
#define SYS_listxattr              215
#define SYS_llistxattr             216
#define SYS_flistxattr             217
#define SYS_removexattr            218
#define SYS_lremovexattr           219
#define SYS_fremovexattr           220
#define SYS_futex                  221
#define SYS_sched_setaffinity      222
#define SYS_sched_getaffinity      223
#define SYS_tuxcall                225
#define SYS_io_setup               227
#define SYS_io_destroy             228
#define SYS_io_getevents           229
#define SYS_io_submit              230
#define SYS_io_cancel              231
#define SYS_set_tid_address        232
#define SYS_fadvise64              233
#define SYS_exit_group             234
#define SYS_lookup_dcookie         235
#define SYS_epoll_create           236
#define SYS_epoll_ctl              237
#define SYS_epoll_wait             238
#define SYS_remap_file_pages       239
#define SYS_timer_create           240
#define SYS_timer_settime          241
#define SYS_timer_gettime          242
#define SYS_timer_getoverrun       243
#define SYS_timer_delete           244
#define SYS_clock_settime          245
#define SYS_clock_gettime          246
#define SYS_clock_getres           247
#define SYS_clock_nanosleep        248
#define SYS_swapcontext            249
#define SYS_tgkill                 250
#define SYS_utimes                 251
#define SYS_statfs64               252
#define SYS_fstatfs64              253
#define SYS_rtas                   255
#define SYS_sys_debug_setcontext   256
#define SYS_migrate_pages          258
#define SYS_mbind                  259
#define SYS_get_mempolicy          260
#define SYS_set_mempolicy          261
#define SYS_mq_open                262
#define SYS_mq_unlink              263
#define SYS_mq_timedsend           264
#define SYS_mq_timedreceive        265
#define SYS_mq_notify              266
#define SYS_mq_getsetattr          267
#define SYS_kexec_load             268
#define SYS_add_key                269
#define SYS_request_key            270
#define SYS_keyctl                 271
#define SYS_waitid                 272
#define SYS_ioprio_set             273
#define SYS_ioprio_get             274
#define SYS_inotify_init           275
#define SYS_inotify_add_watch      276
#define SYS_inotify_rm_watch       277
#define SYS_spu_run                278
#define SYS_spu_create             279
#define SYS_pselect6               280
#define SYS_ppoll                  281
#define SYS_unshare                282
#define SYS_splice                 283
#define SYS_tee                    284
#define SYS_vmsplice               285
#define SYS_openat                 286
#define SYS_mkdirat                287
#define SYS_mknodat                288
#define SYS_fchownat               289
#define SYS_futimesat              290
#define SYS_newfstatat             291
#define SYS_unlinkat               292
#define SYS_renameat               293
#define SYS_linkat                 294
#define SYS_symlinkat              295
#define SYS_readlinkat             296
#define SYS_fchmodat               297
#define SYS_faccessat              298
#define SYS_get_robust_list        299
#define SYS_set_robust_list        300
#define SYS_move_pages             301
#define SYS_getcpu                 302
#define SYS_epoll_pwait            303
#define SYS_utimensat              304
#define SYS_signalfd               305
#define SYS_timerfd_create         306
#define SYS_eventfd                307
#define SYS_sync_file_range2       308
#define SYS_fallocate              309
#define SYS_subpage_prot           310
#define SYS_timerfd_settime        311
#define SYS_timerfd_gettime        312
#define SYS_signalfd4              313
#define SYS_eventfd2               314
#define SYS_epoll_create1          315
#define SYS_dup3                   316
#define SYS_pipe2                  317
#define SYS_inotify_init1          318
#define SYS_perf_event_open        319
#define SYS_preadv                 320
#define SYS_pwritev                321
#define SYS_rt_tgsigqueueinfo      322
#define SYS_fanotify_init          323
#define SYS_fanotify_mark          324
#define SYS_prlimit64              325
#define SYS_socket                 326
#define SYS_bind                   327
#define SYS_connect                328
#define SYS_listen                 329
#define SYS_accept                 330
#define SYS_getsockname            331
#define SYS_getpeername            332
#define SYS_socketpair             333
#define SYS_send                   334
#define SYS_sendto                 335
#define SYS_recv                   336
#define SYS_recvfrom               337
#define SYS_shutdown               338
#define SYS_setsockopt             339
#define SYS_getsockopt             340
#define SYS_sendmsg                341
#define SYS_recvmsg                342
#define SYS_recvmmsg               343
#define SYS_accept4                344
#define SYS_name_to_handle_at      345
#define SYS_open_by_handle_at      346
#define SYS_clock_adjtime          347
#define SYS_syncfs                 348
#define SYS_sendmmsg               349
#define SYS_setns                  350
#define SYS_process_vm_readv       351
#define SYS_process_vm_writev      352
#define SYS_finit_module           353
#define SYS_kcmp                   354
#define SYS_sched_setattr          355
#define SYS_sched_getattr          356
#define SYS_renameat2              357
#define SYS_seccomp                358
#define SYS_getrandom              359
#define SYS_memfd_create           360
#define SYS_bpf                    361
#define SYS_execveat               362
#define SYS_switch_endian          363
#define SYS_userfaultfd            364
#define SYS_membarrier             365
#define SYS_mlock2                 378
#define SYS_copy_file_range        379
#define SYS_preadv2                380
#define SYS_pwritev2               381
#define SYS_kexec_file_load        382
#define SYS_statx                  383
#define SYS_pkey_alloc             384
#define SYS_pkey_free              385
#define SYS_pkey_mprotect          386
#define SYS_rseq                   387
#define SYS_io_pgetevents          388