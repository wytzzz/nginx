
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>


/*
signo：表示信号的编号，通常是整数值。
signame：表示信号的名称，以字符串形式存储。
name：表示信号处理函数的名称，以字符串形式存储。
handler：是一个函数指针，指向信号处理函数。
该函数接受三个参数：signo表示信号编号，siginfo是一个指向siginfo_t结构体的指针，包含了有关信号的更多信息，ucontext是一个指向上下文信息的指针。
*/
typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo, siginfo_t *siginfo, void *ucontext);
} ngx_signal_t;



static void ngx_execute_proc(ngx_cycle_t *cycle, void *data);
static void ngx_signal_handler(int signo, siginfo_t *siginfo, void *ucontext);
static void ngx_process_get_status(void);
static void ngx_unlock_mutexes(ngx_pid_t pid);


/*
这段代码定义了一些全局变量，用于存储与进程和命令行参数相关的信息。
ngx_argc：表示命令行参数的数量。
ngx_argv：是一个字符指针数组，存储命令行参数的字符串。
ngx_os_argv：是一个字符指针数组，存储原始的命令行参数的字符串。

ngx_process_slot：表示当前进程在进程数组中的索引位置。
ngx_channel：用于进程间通信的套接字。
ngx_last_process：表示最后一个进程的索引位置。
ngx_processes：是一个ngx_process_t类型的数组，用于存储进程相关的信息。ngx_process_t结构体包含了进程的ID、名称、状态等信息。
*/
int              ngx_argc;
char           **ngx_argv;
char           **ngx_os_argv;

ngx_int_t        ngx_process_slot;
ngx_socket_t     ngx_channel;
ngx_int_t        ngx_last_process;
ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];

/*
NGX_RECONFIGURE_SIGNAL：重新配置信号，用于重新加载配置文件。
NGX_REOPEN_SIGNAL：重新打开信号，用于重新打开日志文件。
NGX_NOACCEPT_SIGNAL：不接受新连接信号，用于停止接受新连接。
NGX_TERMINATE_SIGNAL：终止信号，用于停止Nginx服务。
NGX_SHUTDOWN_SIGNAL：关闭信号，用于平滑关闭Nginx服务。
NGX_CHANGEBIN_SIGNAL：切换二进制文件信号，用于平滑升级Nginx二进制文件。
SIGALRM：定时器信号。
SIGINT：终端中断信号。
SIGIO：异步I/O事件信号。
SIGCHLD：子进程状态改变信号。
SIGSYS：系统调用信号，忽略处理。
SIGPIPE：管道破裂信号，忽略处理。
*/
ngx_signal_t  signals[] = {
    { ngx_signal_value(NGX_RECONFIGURE_SIGNAL),
      "SIG" ngx_value(NGX_RECONFIGURE_SIGNAL),
      "reload",
      ngx_signal_handler },

    { ngx_signal_value(NGX_REOPEN_SIGNAL),
      "SIG" ngx_value(NGX_REOPEN_SIGNAL),
      "reopen",
      ngx_signal_handler },

    { ngx_signal_value(NGX_NOACCEPT_SIGNAL),
      "SIG" ngx_value(NGX_NOACCEPT_SIGNAL),
      "",
      ngx_signal_handler },

    { ngx_signal_value(NGX_TERMINATE_SIGNAL),
      "SIG" ngx_value(NGX_TERMINATE_SIGNAL),
      "stop",
      ngx_signal_handler },

    { ngx_signal_value(NGX_SHUTDOWN_SIGNAL),
      "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL),
      "quit",
      ngx_signal_handler },

    { ngx_signal_value(NGX_CHANGEBIN_SIGNAL),
      "SIG" ngx_value(NGX_CHANGEBIN_SIGNAL),
      "",
      ngx_signal_handler },

    { SIGALRM, "SIGALRM", "", ngx_signal_handler },

    { SIGINT, "SIGINT", "", ngx_signal_handler },

    { SIGIO, "SIGIO", "", ngx_signal_handler },

    { SIGCHLD, "SIGCHLD", "", ngx_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", NULL },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", NULL },

    { 0, NULL, "", NULL }
};



//创建新进程
/*
cycle：指向表示Nginx周期的ngx_cycle_t结构体的指针。
proc：指向要生成的进程的函数指针。
data：要传递给进程的额外数据。
name：表示进程名称的字符串。
respawn：一个整数，表示进程的重启行为。
*/
ngx_pid_t
ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data,
    char *name, ngx_int_t respawn)
{
    u_long     on;
    ngx_pid_t  pid;
    ngx_int_t  s;
    
    if (respawn >= 0) {
        s = respawn;

    } else {
        //否则，通过循环遍历ngx_processes数组，找到一个pid为-1的空闲位置，
        //将s设置为该位置的索引。如果找不到空闲位置，则会记录一个错误信息并返回NGX_INVALID_PID
        for (s = 0; s < ngx_last_process; s++) {
            if (ngx_processes[s].pid == -1) {
                break;
            }
        }

        if (s == NGX_MAX_PROCESSES) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "no more than %d processes can be spawned",
                          NGX_MAX_PROCESSES);
            return NGX_INVALID_PID;
        }
    }

    //如果respawn不等于NGX_PROCESS_DETACHED，则创建一个UNIX域套接字对，
    //否则，将ngx_processes[s].channel[0]和ngx_processes[s].channel[1]设置为-1。
    if (respawn != NGX_PROCESS_DETACHED) {

        /* Solaris 9 still has no AF_LOCAL */
        
        //创建一对socket套接字，存储在ngx_processes[s].channel中。
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, ngx_processes[s].channel) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return NGX_INVALID_PID;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       ngx_processes[s].channel[0],
                       ngx_processes[s].channel[1]);

        if (ngx_nonblocking(ngx_processes[s].channel[0]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (ngx_nonblocking(ngx_processes[s].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        on = 1;
        // 进行一些设置，如非阻塞、异步IO和文件描述符的设置。
        if (ioctl(ngx_processes[s].channel[0], FIOASYNC, &on) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[0], F_SETOWN, ngx_pid) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        ngx_channel = ngx_processes[s].channel[1];

    } else {
        ngx_processes[s].channel[0] = -1;
        ngx_processes[s].channel[1] = -1;
    }
    
    //将s赋值给全局变量ngx_process_slot。
    ngx_process_slot = s;


    pid = fork();
    
    //调用fork()创建一个新进程。根据返回值的不同，执行不同的逻辑：
    switch (pid) {

    case -1:
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "fork() failed while spawning \"%s\"", name);
        ngx_close_channel(ngx_processes[s].channel, cycle->log);
        return NGX_INVALID_PID;
    //如果返回值为0，表示当前代码在子进程中运行。
    //将一些全局变量进行更新，并调用proc(cycle, data)执行实际的进程逻辑
    case 0:
        ngx_parent = ngx_pid;
        ngx_pid = ngx_getpid();
        proc(cycle, data);
        break;
    
    //如果返回值大于0，表示当前代码在父进程中运行，不做任何特殊处理。
    default:
        break;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);
    
    ngx_processes[s].pid = pid;
    ngx_processes[s].exited = 0;

    if (respawn >= 0) {
        return pid;
    }

    ngx_processes[s].proc = proc;
    ngx_processes[s].data = data;
    ngx_processes[s].name = name;
    ngx_processes[s].exiting = 0;

    switch (respawn) {

    case NGX_PROCESS_NORESPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_SPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_DETACHED:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 1;
        break;
    }

    if (s == ngx_last_process) {
        ngx_last_process++;
    }

    return pid;
}


ngx_pid_t
ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
{
    return ngx_spawn_process(cycle, ngx_execute_proc, ctx, ctx->name,
                             NGX_PROCESS_DETACHED);
}


static void
ngx_execute_proc(ngx_cycle_t *cycle, void *data)
{
    ngx_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}


//该函数会遍历信号数组signals，为每个信号注册相应的信号处理函数。
ngx_int_t
ngx_init_signals(ngx_log_t *log)
{
    ngx_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        ngx_memzero(&sa, sizeof(struct sigaction));
        
        //如果信号的处理函数存在（即sig->handler非空），
        //则将sig->handler赋值给sa.sa_sigaction，
        //并设置sa.sa_flags为SA_SIGINFO，表示使用带有附加信息的信号处理函数。
        if (sig->handler) {
            sa.sa_sigaction = sig->handler;
            sa.sa_flags = SA_SIGINFO;
        
        //如果信号的处理函数不存在（即sig->handler为空），则将SIG_IGN赋值给sa.sa_handler，表示忽略该信号。
        } else {
            sa.sa_handler = SIG_IGN;
        }
        
        //使用sigemptyset函数将sa.sa_mask清空，以确保在信号处理函数执行期间不会被其他信号中断。
        sigemptyset(&sa.sa_mask);
        //调用sigaction函数为当前信号注册信号处理函数，并将sa作为参数传递。如果注册失败，将根据编译选项输出日志信息
        if (sigaction(sig->signo, &sa, NULL) == -1) {
#if (NGX_VALGRIND)
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "sigaction(%s) failed, ignored", sig->signame);
#else
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "sigaction(%s) failed", sig->signame);
            return NGX_ERROR;
#endif
        }
    }
    
    //遍历完所有信号后，返回NGX_OK表示初始化信号处理成功。
    return NGX_OK;
}

/*
该函数接收三个参数：signo表示接收到的信号编号，siginfo表示信号的附加信息，ucontext表示信号的上下文
*/

static void
ngx_signal_handler(int signo, siginfo_t *siginfo, void *ucontext)
{
    //定义变量action用于记录信号处理的动作，变量ignore用于标识是否忽略信号，变量err用于保存当前的错误码。
    char            *action;
    ngx_int_t        ignore;
    ngx_err_t        err;
    ngx_signal_t    *sig;

    ignore = 0;

    err = ngx_errno;
    //通过遍历信号数组signals，找到与接收到的信号编号一致的信号结构体sig。
    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
    
    //更新时间，调用ngx_time_sigsafe_update()函数，用于更新时间相关的信息
    ngx_time_sigsafe_update();

    action = "";
    
    //根据当前的进程类型(ngx_process)和接收到的信号进行不同的处理
    switch (ngx_process) {
    
    //如果是主进程或单进程模式，根据不同的信号进行相应的操作，例如设置标志位、输出日志等。
    case NGX_PROCESS_MASTER:
    case NGX_PROCESS_SINGLE:
        switch (signo) {

        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;

        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            if (ngx_daemonized) {
                ngx_noaccept = 1;
                action = ", stop accepting connections";
            }
            break;

        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
            ngx_reconfigure = 1;
            action = ", reconfiguring";
            break;

        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
            if (ngx_getppid() == ngx_parent || ngx_new_binary > 0) {

                /*
                 * Ignore the signal in the new binary if its parent is
                 * not changed, i.e. the old binary's process is still
                 * running.  Or ignore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */

                action = ", ignoring";
                ignore = 1;
                break;
            }

            ngx_change_binary = 1;
            action = ", changing binary";
            break;

        case SIGALRM:
            ngx_sigalrm = 1;
            break;

        case SIGIO:
            ngx_sigio = 1;
            break;

        case SIGCHLD:
            ngx_reap = 1;
            break;
        }

        break;

    case NGX_PROCESS_WORKER:
    case NGX_PROCESS_HELPER:
        switch (signo) {

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            if (!ngx_daemonized) {
                break;
            }
            ngx_debug_quit = 1;
            /* fall through */
        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;

        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;

        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }
    
    //根据是否存在信号附加信息siginfo，输出相应的日志信息，包括信号编号、信号名称、发送信号的进程ID以及信号处理的动作。
    if (siginfo && siginfo->si_pid) {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                      "signal %d (%s) received from %P%s",
                      signo, sig->signame, siginfo->si_pid, action);

    } else {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                      "signal %d (%s) received%s",
                      signo, sig->signame, action);
    }
    
    //如果ignore为真，表示正在进行二进制文件切换过程中，输出对应的日志信息。
    if (ignore) {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }
    
    //如果接收到的信号是SIGCHLD，调用ngx_process_get_status()函数获取子进程的状态信息
    if (signo == SIGCHLD) {
        ngx_process_get_status();
    }
    
    //最后，将之前保存的错误码err设置回去。
    ngx_set_errno(err);
}


static void
ngx_process_get_status(void)
{
    //定义变量status用于保存子进程的退出状态，变量process用于保存子进程的名称，变量pid用于保存子进程的进程ID，
    //变量err用于保存错误码，变量i用于循环计数，变量one用于标识是否已经处理了至少一个子进程。
    int              status;
    char            *process;
    ngx_pid_t        pid;
    ngx_err_t        err;
    ngx_int_t        i;
    ngx_uint_t       one;

    one = 0;
    
    //进入一个无限循环，通过waitpid()函数非阻塞地等待任意子进程的退出状态。
    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);
        
        //如果waitpid()返回的pid为0，表示没有子进程退出，函数返回
        if (pid == 0) {
            return;
        }
        
        //如果waitpid()返回的pid为-1，表示发生了错误。根据不同的错误码进行处理：
        if (pid == -1) {
            err = ngx_errno;
            
            //如果错误码是NGX_EINTR，表示waitpid()被信号中断，继续循环等待下一个子进程退出状态。
            if (err == NGX_EINTR) {
                continue;
            }
            
            //如果错误码是NGX_ECHILD且已经处理过至少一个子进程，表示所有子进程已经处理完毕，函数返回。
            if (err == NGX_ECHILD && one) {
                return;
            }

            /*
             * Solaris always calls the signal handler for each exited process
             * despite waitpid() may be already called for this process.
             *
             * When several processes exit at the same time FreeBSD may
             * erroneously call the signal handler for exited process
             * despite waitpid() may be already called for this process.
             */
            
            //如果错误码是NGX_ECHILD且还没有处理过任何子进程，表示没有子进程需要处理，输出相应的日志信息，函数返回。
            if (err == NGX_ECHILD) {
                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, err,
                              "waitpid() failed");
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                          "waitpid() failed");
            return;
        }
        //遍历存储子进程信息的数组ngx_processes，查找与当前退出的子进程pid相匹配的子进程信息。
        //如果执行到这里，表示成功获取到了一个子进程的退出状态，设置one为1，表示已经处理过至少一个子进程。
        one = 1;
        process = "unknown process";
        
        //如果找到了匹配的子进程信息，更新子进程的状态和退出标志，并将子进程的名称赋值给process。
        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_processes[i].pid == pid) {
                ngx_processes[i].status = status;
                ngx_processes[i].exited = 1;
                process = ngx_processes[i].name;
                break;
            }
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");
#else
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d",
                          process, pid, WTERMSIG(status));
#endif

        } else {
            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                          "%s %P exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && ngx_processes[i].respawn) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited with fatal code %d "
                          "and cannot be respawned",
                          process, pid, WEXITSTATUS(status));
            ngx_processes[i].respawn = 0;
        }

        ngx_unlock_mutexes(pid);
    }
}


static void
ngx_unlock_mutexes(ngx_pid_t pid)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;
    ngx_slab_pool_t  *sp;

    /*
     * unlock the accept mutex if the abnormally exited process
     * held it
     */

    if (ngx_accept_mutex_ptr) {
        (void) ngx_shmtx_force_unlock(&ngx_accept_mutex, pid);
    }

    /*
     * unlock shared memory mutexes if held by the abnormally exited
     * process
     */

    part = (ngx_list_part_t *) &ngx_cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        sp = (ngx_slab_pool_t *) shm_zone[i].shm.addr;

        if (ngx_shmtx_force_unlock(&sp->mutex, pid)) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "shared memory zone \"%V\" was locked by %P",
                          &shm_zone[i].shm.name, pid);
        }
    }
}


void
ngx_debug_point(void)
{
    ngx_core_conf_t  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    switch (ccf->debug_points) {

    case NGX_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    case NGX_DEBUG_POINTS_ABORT:
        ngx_abort();
    }
}


ngx_int_t
ngx_os_signal_process(ngx_cycle_t *cycle, char *name, ngx_pid_t pid)
{
    ngx_signal_t  *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        if (ngx_strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) != -1) {
                return 0;
            }

            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "kill(%P, %d) failed", pid, sig->signo);
        }
    }

    return 1;
}
