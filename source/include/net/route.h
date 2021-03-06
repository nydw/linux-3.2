/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP router.
 *
 * Version:	@(#)route.h	1.0.4	05/27/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 * Fixes:
 *		Alan Cox	:	Reformatted. Added ip_rt_local()
 *		Alan Cox	:	Support for TCP parameters.
 *		Alexey Kuznetsov:	Major changes for new routing code.
 *		Mike McLagan    :	Routing by source
 *		Robert Olsson   :	Added rt_cache statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _ROUTE_H
#define _ROUTE_H

#include <net/dst.h>
#include <net/inetpeer.h>
#include <net/flow.h>
#include <net/inet_sock.h>
#include <linux/in_route.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <linux/ip.h>
#include <linux/cache.h>
#include <linux/security.h>

#define RTO_ONLINK	0x01

#define RT_CONN_FLAGS(sk)   (RT_TOS(inet_sk(sk)->tos) | sock_flag(sk, SOCK_LOCALROUTE))

struct fib_nh;
struct inet_peer;
struct fib_info;


/*
路由查询结果(struct fib_result)还不能直接供发送IP数据报使用，
接下来，还必须根据这个查询结果生成一个路由目的入口(dst_entry)。
根据目的入口才可以发送IP 数据报，目的入口用结构体struct dst_entry表示，
在实际使用时，还在它的外面包装了一层，形成一个结构体struct rtable。
*/

struct rtable {  //lgx_mark 路由表结构
    struct dst_entry	dst;  // 路由项定义

    /* Lookup key. */
    __be32			rt_key_dst;  //   路由的目的地址
    __be32			rt_key_src;  //   路由的源地址

    int			rt_genid; // 路由表使用的随机数


    /*
      rt_flags 一组标志位，
      按目的入口查询的执行顺序：
      如果路由使用本地环回接口，则rt_flags上加标志RTCF_LOCAL
      如果路由结果类型是广播，则加标志RTCF_BROADCAST和RTCF_LOCAL
      如果结果是组播，则加标志RTCF_MULTICAST和 RTCF_LOCAL，该标志最终决定了目的入口使用哪一个IP数据报输入函数和输出函数
      如果是RTCF_LOCAL，则使用输入函数ip_local_deliver()
      如果是RTCF_BROADCAST或RTCF_MULTICAST，并且带有RTCF_LOCAL标志，并且输出设备不是环回接口设备，则使用输出函数ip_mc_output()，
      否则使用输出函数ip_output()
    */

    unsigned		rt_flags; // 路由标志

    /*
     rt_type 路由类型，
      如果路由是LOOPBACK，则置类型为RTN_LOCAL，单播路由类型为RTN_UNICAST，
      如果目的地址为 0xFFFFFFFF，则路由类型为RTN_BROADCAST，
      如果目的地址是组播地址，则路由类型为RTN_MULTICAST。
      rt_type跟 rt_flags关系比较密切。
    */
    __u16			rt_type;  // 路由类型   RTN_LOCAL
    __u8			rt_key_tos;

    __be32			rt_dst;	/* Path destination 路由的目标地址	*/
    __be32			rt_src;	/* Path source 路由的源地址		*/
    int			rt_route_iif;
    int			rt_iif;    // 路由的输入设备接口的索引号
    int			rt_oif;    // 路由的输出设备接口的索引号
    __u32	    rt_mark;

    /* Info on neighbour */
    __be32		rt_gateway; // 路由网关的IP地址

    /* Miscellaneous cached information */
    __be32		rt_spec_dst; /* 指定的目标地址*/
    u32			rt_peer_genid;
    struct inet_peer	*peer; /* long-living peer info 刚刚访问的目标主机的信息 */
    struct fib_info		*fi; /* for client ref to shared metrics */

};

static inline bool rt_is_input_route(const struct rtable *rt)
{
    return rt->rt_route_iif != 0;
}

static inline bool rt_is_output_route(const struct rtable *rt) //是否指定接收网络设备
{
    return rt->rt_route_iif == 0;
}

struct ip_rt_acct {
    __u32 	o_bytes;  // 发出的字节数
    __u32 	o_packets;
    __u32 	i_bytes;  // 接收的字节数
    __u32 	i_packets;
};

struct rt_cache_stat {
    unsigned int in_hit;
    unsigned int in_slow_tot;
    unsigned int in_slow_mc;
    unsigned int in_no_route;
    unsigned int in_brd;
    unsigned int in_martian_dst;
    unsigned int in_martian_src;
    unsigned int out_hit;
    unsigned int out_slow_tot;
    unsigned int out_slow_mc;
    unsigned int gc_total;
    unsigned int gc_ignored;
    unsigned int gc_goal_miss;
    unsigned int gc_dst_overflow;
    unsigned int in_hlist_search;
    unsigned int out_hlist_search;
};

extern struct ip_rt_acct __percpu *ip_rt_acct;

struct in_device;
extern int		ip_rt_init(void);
extern void		ip_rt_redirect(__be32 old_gw, __be32 dst, __be32 new_gw,
                               __be32 src, struct net_device *dev);
extern void		rt_cache_flush(struct net *net, int how);
extern void		rt_cache_flush_batch(struct net *net);
extern struct rtable *__ip_route_output_key(struct net *, struct flowi4 *flp);
extern struct rtable *ip_route_output_flow(struct net *, struct flowi4 *flp,
        struct sock *sk);
extern struct dst_entry *ipv4_blackhole_route(struct net *net, struct dst_entry *dst_orig);

static inline struct rtable *ip_route_output_key(struct net *net, struct flowi4 *flp)
{
    return ip_route_output_flow(net, flp, NULL);
}

static inline struct rtable *ip_route_output(struct net *net, __be32 daddr,
        __be32 saddr, u8 tos, int oif)
{
    struct flowi4 fl4 = {
        .flowi4_oif = oif,
        .daddr = daddr,
        .saddr = saddr,
        .flowi4_tos = tos,
    };
    return ip_route_output_key(net, &fl4);
}

static inline struct rtable *ip_route_output_ports(struct net *net, struct flowi4 *fl4,
        struct sock *sk,
        __be32 daddr, __be32 saddr,
        __be16 dport, __be16 sport,
        __u8 proto, __u8 tos, int oif)
{
    flowi4_init_output(fl4, oif, sk ? sk->sk_mark : 0, tos,
                       RT_SCOPE_UNIVERSE, proto,
                       sk ? inet_sk_flowi_flags(sk) : 0,
                       daddr, saddr, dport, sport);
    if (sk)
        security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
    return ip_route_output_flow(net, fl4, sk);
}

static inline struct rtable *ip_route_output_gre(struct net *net, struct flowi4 *fl4,
        __be32 daddr, __be32 saddr,
        __be32 gre_key, __u8 tos, int oif)
{
    memset(fl4, 0, sizeof(*fl4));
    fl4->flowi4_oif = oif;
    fl4->daddr = daddr;
    fl4->saddr = saddr;
    fl4->flowi4_tos = tos;
    fl4->flowi4_proto = IPPROTO_GRE;
    fl4->fl4_gre_key = gre_key;
    return ip_route_output_key(net, fl4);
}

extern int ip_route_input_common(struct sk_buff *skb, __be32 dst, __be32 src,
                                 u8 tos, struct net_device *devin, bool noref);

static inline int ip_route_input(struct sk_buff *skb, __be32 dst, __be32 src,
                                 u8 tos, struct net_device *devin)
{
    return ip_route_input_common(skb, dst, src, tos, devin, false);
}

static inline int ip_route_input_noref(struct sk_buff *skb, __be32 dst, __be32 src,
                                       u8 tos, struct net_device *devin)
{
    return ip_route_input_common(skb, dst, src, tos, devin, true);
}

extern unsigned short	ip_rt_frag_needed(struct net *net, const struct iphdr *iph,
        unsigned short new_mtu, struct net_device *dev);
extern void		ip_rt_send_redirect(struct sk_buff *skb);

extern unsigned		inet_addr_type(struct net *net, __be32 addr);
extern unsigned		inet_dev_addr_type(struct net *net, const struct net_device *dev, __be32 addr);
extern void		ip_rt_multicast_event(struct in_device *);
extern int		ip_rt_ioctl(struct net *, unsigned int cmd, void __user *arg);
extern void		ip_rt_get_source(u8 *src, struct sk_buff *skb, struct rtable *rt);
extern int		ip_rt_dump(struct sk_buff *skb,  struct netlink_callback *cb);

struct in_ifaddr;
extern void fib_add_ifaddr(struct in_ifaddr *);
extern void fib_del_ifaddr(struct in_ifaddr *, struct in_ifaddr *);

static inline void ip_rt_put(struct rtable * rt)
{
    if (rt)
        dst_release(&rt->dst);
}

#define IPTOS_RT_MASK	(IPTOS_TOS_MASK & ~3)

extern const __u8 ip_tos2prio[16];

static inline char rt_tos2priority(u8 tos)
{
    return ip_tos2prio[IPTOS_TOS(tos)>>1];
}

/* ip_route_connect() and ip_route_newports() work in tandem whilst
 * binding a socket for a new outgoing connection.
 *
 * In order to use IPSEC properly, we must, in the end, have a
 * route that was looked up using all available keys including source
 * and destination ports.
 *
 * However, if a source port needs to be allocated (the user specified
 * a wildcard source port) we need to obtain addressing information
 * in order to perform that allocation.
 *
 * So ip_route_connect() looks up a route using wildcarded source and
 * destination ports in the key, simply so that we can get a pair of
 * addresses to use for port allocation.
 *
 * Later, once the ports are allocated, ip_route_newports() will make
 * another route lookup if needed to make sure we catch any IPSEC
 * rules keyed on the port information.
 *
 * The callers allocate the flow key on their stack, and must pass in
 * the same flowi4 object to both the ip_route_connect() and the
 * ip_route_newports() calls.
 */

static inline void ip_route_connect_init(struct flowi4 *fl4, __be32 dst, __be32 src,
        u32 tos, int oif, u8 protocol,
        __be16 sport, __be16 dport,
        struct sock *sk, bool can_sleep)
{
    __u8 flow_flags = 0;

    if (inet_sk(sk)->transparent)
        flow_flags |= FLOWI_FLAG_ANYSRC;
    if (protocol == IPPROTO_TCP)
        flow_flags |= FLOWI_FLAG_PRECOW_METRICS;
    if (can_sleep)
        flow_flags |= FLOWI_FLAG_CAN_SLEEP;

    flowi4_init_output(fl4, oif, sk->sk_mark, tos, RT_SCOPE_UNIVERSE,
                       protocol, flow_flags, dst, src, dport, sport);
}

static inline struct rtable *ip_route_connect(struct flowi4 *fl4,   // lgx_mark
        __be32 dst, __be32 src, u32 tos,
        int oif, u8 protocol,  // oif 发送设备 protocol 指定的ip协议
        __be16 sport, __be16 dport,
        struct sock *sk, bool can_sleep) // 用于发送的sock结构
{
    struct net *net = sock_net(sk);
    struct rtable *rt;

    ip_route_connect_init(fl4, dst, src, tos, oif, protocol,
                          sport, dport, sk, can_sleep);

    if (!dst || !src)   // 如果没有指定目标地址和源地址，就要查看路由表
    {
        rt = __ip_route_output_key(net, fl4);
		
        if (IS_ERR(rt)) return rt;

        ip_rt_put(rt);  // 递减路由表的路由项计数器
        
        flowi4_update_output(fl4, oif, tos, fl4->daddr, fl4->saddr); // 使用路由表的目标地址/源地址
    }
    security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
    return ip_route_output_flow(net, fl4, sk); // 再次查找并调整地址
}

static inline struct rtable *ip_route_newports(struct flowi4 *fl4, struct rtable *rt,
        __be16 orig_sport, __be16 orig_dport,
        __be16 sport, __be16 dport,
        struct sock *sk)
{
    if (sport != orig_sport || dport != orig_dport) {
        fl4->fl4_dport = dport;
        fl4->fl4_sport = sport;
        ip_rt_put(rt);
        flowi4_update_output(fl4, sk->sk_bound_dev_if,
                             RT_CONN_FLAGS(sk), fl4->daddr,
                             fl4->saddr);
        security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
        return ip_route_output_flow(sock_net(sk), fl4, sk);
    }
    return rt;
}

extern void rt_bind_peer(struct rtable *rt, __be32 daddr, int create);

static inline struct inet_peer *rt_get_peer(struct rtable *rt, __be32 daddr)
{
    if (rt->peer)
        return rt->peer;

    rt_bind_peer(rt, daddr, 0);
    return rt->peer;
}

static inline int inet_iif(const struct sk_buff *skb)
{
    return skb_rtable(skb)->rt_iif;
}

extern int sysctl_ip_default_ttl;

static inline int ip4_dst_hoplimit(const struct dst_entry *dst)
{
    int hoplimit = dst_metric_raw(dst, RTAX_HOPLIMIT);

    if (hoplimit == 0)
        hoplimit = sysctl_ip_default_ttl;
    return hoplimit;
}

#endif	/* _ROUTE_H */
