
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);
/*
ngx_pid_t pid：表示进程的进程ID（PID）。
int status：表示进程的状态。
ngx_socket_t channel[2]：表示进程的通信通道，是一个长度为2的数组，用于在进程之间进行通信。
ngx_spawn_proc_pt proc：是一个函数指针，指向要生成的进程的函数。
void *data：表示要传递给进程的额外数据。
char *name：表示进程的名称。

以下是结构体中的一些标志位（以位字段的形式表示）：

unsigned respawn:1：表示进程是否需要重启。
unsigned just_spawn:1：表示进程是否刚刚生成。
unsigned detached:1：表示进程是否以分离（detached）的方式运行。
unsigned exiting:1：表示进程是否正在退出。
unsigned exited:1：表示进程是否已经退出。

这个结构体用于存储一个进程的各种属性和状态信息，
可以在代码中使用该结构体的实例来管理和操作进程。通过设置结构体中的字段，可以控制进程的行为和状态，
并进行进程间通信。

*/
typedef struct {
    ngx_pid_t           pid;
    int                 status;
    ngx_socket_t        channel[2];

    ngx_spawn_proc_pt   proc;
    void               *data;
    char               *name;

    unsigned            respawn:1;
    unsigned            just_spawn:1;
    unsigned            detached:1;
    unsigned            exiting:1;
    unsigned            exited:1;
} ngx_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024

/*
NGX_PROCESS_NORESPAWN：表示进程不需要重启，其值为-1。
NGX_PROCESS_JUST_SPAWN：表示仅生成进程，不进行重启，其值为-2。
NGX_PROCESS_RESPAWN：表示生成进程并进行重启，其值为-3。
NGX_PROCESS_JUST_RESPAWN：表示仅进行进程重启，不生成新进程，其值为-4。
NGX_PROCESS_DETACHED：表示进程以分离（detached）的方式运行，其值为-5。*/
#define NGX_PROCESS_NORESPAWN     -1
#define NGX_PROCESS_JUST_SPAWN    -2
#define NGX_PROCESS_RESPAWN       -3
#define NGX_PROCESS_JUST_RESPAWN  -4
#define NGX_PROCESS_DETACHED      -5


#define ngx_getpid   getpid
#define ngx_getppid  getppid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_pid_t      ngx_parent;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
