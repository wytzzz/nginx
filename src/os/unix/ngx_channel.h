
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CHANNEL_H_INCLUDED_
#define _NGX_CHANNEL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

/*
command：一个ngx_uint_t类型的字段，用于表示通道的命令。
pid：一个ngx_pid_t类型的字段，用于表示进程的PID。
slot：一个ngx_int_t类型的字段，用于表示进程的槽位索引。
fd：一个ngx_fd_t类型的字段，用于表示文件描述符。
这个结构体类型的作用是在进程间传递通道相关的信息。
通过使用这个结构体，可以将命令、进程PID、槽位索引和文件描述符等信息打包在一起，方便在进程间进行通信和共享。
*/
typedef struct {
    ngx_uint_t  command;
    ngx_pid_t   pid;
    ngx_int_t   slot;
    ngx_fd_t    fd;
} ngx_channel_t;


ngx_int_t ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd,
    ngx_int_t event, ngx_event_handler_pt handler);
void ngx_close_channel(ngx_fd_t *fd, ngx_log_t *log);


#endif /* _NGX_CHANNEL_H_INCLUDED_ */
