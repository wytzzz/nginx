
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

/*
ngx_posted_accept_events是一个事件队列，用于存储已推送的、需要处理的接受事件。当有新的连接请求到达时，将会将该事件添加到ngx_posted_accept_events队列中。
ngx_posted_next_events是一个事件队列，用于存储已推送的、需要处理的下一事件。在处理事件时，如果发现有下一事件需要立即处理，则将其添加到ngx_posted_next_events队列中。
ngx_posted_events是一个事件队列，用于存储已推送的、需要处理的其他事件。这些事件可能是非接受事件，比如读取、写入等事件
*/
ngx_queue_t  ngx_posted_accept_events;
ngx_queue_t  ngx_posted_next_events;
ngx_queue_t  ngx_posted_events;


void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;
    
    //循环处理 posted 队列中的事件
    while (!ngx_queue_empty(posted)) {

        q = ngx_queue_head(posted);
        // 从队列节点中获取对应的事件
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);
        // 从 posted 队列中移除该事件
        ngx_delete_posted_event(ev);
        
        // 调用事件的处理函数
        ev->handler(ev);
    }
}


//用于将已推送的下一事件队列中的事件移动到当前事件队列中。
void
ngx_event_move_posted_next(ngx_cycle_t *cycle)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;
    
    //使用ngx_queue_head函数获取ngx_posted_next_events队列的头部节点。
    //遍历ngx_posted_next_events队列，直到遍历到尾部哨兵节点为止。
    for (q = ngx_queue_head(&ngx_posted_next_events);
         q != ngx_queue_sentinel(&ngx_posted_next_events);
         q = ngx_queue_next(q))
    {
        //在循环内部，使用ngx_queue_data宏获取当前节点对应的ngx_event_t结构体指针。
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted next event %p", ev);
        
        //设置事件的ready字段为1，表示事件已准备就绪。
        //设置事件的available字段为-1，表示可用数据长度未知。
        ev->ready = 1;
        ev->available = -1;
    }
    
    //使用ngx_queue_add函数将ngx_posted_next_events队列中的事件节点添加到ngx_posted_events队列中。
    ngx_queue_add(&ngx_posted_events, &ngx_posted_next_events);
    //使用ngx_queue_init函数将ngx_posted_next_events队列重新初始化为空队列。
    ngx_queue_init(&ngx_posted_next_events);
}
