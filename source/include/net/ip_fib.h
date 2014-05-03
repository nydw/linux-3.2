/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <net/flow.h>
#include <linux/seq_file.h>
#include <net/fib_rules.h>

struct fib_config { // 路由配置结构
    u8			fc_dst_len;  // 地址长度
    u8			fc_tos;  // 服务类型TOS
    u8			fc_protocol;  // 路由协议
    u8			fc_scope;  // 路由范围    RT_SCOPE_HOST
    u8			fc_type;  // 路由类型     RTN_LOCAL
    /* 3 bytes unused */
    u32			fc_table;  // 路由函数表
    __be32			fc_dst; // 路由目的地址
    __be32			fc_gw;  // 网关
    int			fc_oif;  // 网络设备ID
    u32			fc_flags; // 路由标志位
    u32			fc_priority;  // 路由优先级
    __be32			fc_prefsrc;  // 指定的ip地址
    struct nlattr		*fc_mx;  // 指定netlink属性队列
    struct rtnexthop	*fc_mp;  // 配置的跳转结构队列
    int			fc_mx_len;  // 全部netlink属性队列的总长度
    int			fc_mp_len;  // 全部配置跳转结构的总长度
    u32			fc_flow;
    u32			fc_nlflags;  //netlink的标志位
    struct nl_info		fc_nlinfo;
};

struct fib_info;


/*

一个路由（fib_alias）可能有多个fib_nh结构，
它表示这个路由有多个下一跳地址，即它是多路径（multipath）的.
下一跳地址的选择也有多种算法，这些算法都是基于nh_weight， nh_power域的.
nh_hash域则是用于将nh_hash链入HASH表的.

*/

struct fib_nh {
    struct net_device	*nh_dev; // 指向网络设备结构
    struct hlist_node	nh_hash; // 链入到路由设备队列的哈希节点
    struct fib_info		*nh_parent; // 指向包含这个跳转的路由信息结构
    unsigned		    nh_flags;  //跳转标志位
    unsigned char		nh_scope; // 路由的跳转范围
#ifdef CONFIG_IP_ROUTE_MULTIPATH
    int			nh_weight;  // 跳转压力
    int			nh_power;  // 跳转能力
#endif
#ifdef CONFIG_IP_ROUTE_CLASSID
    __u32			nh_tclassid;
#endif
    int			nh_oif;  // 发送设备的ID
    __be32			nh_gw;  // 网关的IP地址
    __be32			nh_saddr;
    int			nh_saddr_genid;
};

/*
 * This structure contains data shared by many of routes.
 */

struct fib_info {  // 下一跳路由信息结构
    struct hlist_node	fib_hash;  // 链入两个hash链表中
    struct hlist_node	fib_lhash;
    struct net		*fib_net;  // 所属网络空间
    int			fib_treeref;   // 路由信息结构的使用计数器
    atomic_t		fib_clntref;  // 是否释放路由信息结构的计数器
    unsigned		fib_flags;  // 标志位
    unsigned char		fib_dead;  // 标志着路由被删除
    unsigned char		fib_protocol; // 安装路由协议
    unsigned char		fib_scope;
    __be32			fib_prefsrc;  // 指定的源IP地址，源地址是与目标地址组成一个路由
    u32			fib_priority;  // 路由的优先级
    u32			*fib_metrics;    // 用来保存负载值，包括mtu和mss等内容
#define fib_mtu fib_metrics[RTAX_MTU-1]  //mtu
#define fib_window fib_metrics[RTAX_WINDOW-1] //窗口值
#define fib_rtt fib_metrics[RTAX_RTT-1]  // rtt
#define fib_advmss fib_metrics[RTAX_ADVMSS-1] //对外公开的mss值
    int			fib_nhs;  // 跳转结构fib_nh的长度
#ifdef CONFIG_IP_ROUTE_MULTIPATH
    int			fib_power;  // 支持多路径是使用
#endif
    struct rcu_head		rcu;
    struct fib_nh		fib_nh[0];   // 下一个跳转结构
#define fib_dev		fib_nh[0].nh_dev

};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

struct fib_table;
struct fib_result {
    unsigned char	prefixlen;
    unsigned char	nh_sel;
    unsigned char	type;  //记录地址类型
    unsigned char	scope;
    struct fib_info *fi;
    struct fib_table *table;
    struct list_head *fa_head;
#ifdef CONFIG_IP_MULTIPLE_TABLES
    struct fib_rule	*r;
#endif
};

struct fib_result_nl {
    __be32		fl_addr;   /* To be looked up*/
    u32		fl_mark;
    unsigned char	fl_tos;
    unsigned char   fl_scope;
    unsigned char   tb_id_in;

    unsigned char   tb_id;      /* Results */
    unsigned char	prefixlen;
    unsigned char	nh_sel;
    unsigned char	type;
    unsigned char	scope;
    int             err;
};

#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])

#define FIB_TABLE_HASHSZ 2

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])

#define FIB_TABLE_HASHSZ 256

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

extern __be32 fib_info_update_nh_saddr(struct net *net, struct fib_nh *nh);

#define FIB_RES_SADDR(net, res)				\
	((FIB_RES_NH(res).nh_saddr_genid ==		\
	  atomic_read(&(net)->ipv4.dev_addr_genid)) ?	\
	 FIB_RES_NH(res).nh_saddr :			\
	 fib_info_update_nh_saddr((net), &FIB_RES_NH(res)))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

#define FIB_RES_PREFSRC(net, res)	((res).fi->fib_prefsrc ? : \
					 FIB_RES_SADDR(net, res))

struct fib_table {  // 路由表的总根
    struct hlist_node tb_hlist;  // 哈希链入节点
    u32		tb_id;       // 标识符 255是LOCAL表，254是MAIN表。
    int		tb_default;  // 路由信息结构的队列序号
    int		tb_num_default;
    unsigned long	tb_data[0];  // 而fn_hash的实现则是fib_table的最后一个参数tb_data[0]。
};

/*查询路由信息的操作方法*/
extern int fib_table_lookup(struct fib_table *tb, const struct flowi4 *flp,struct fib_result *res, int fib_flags); //路由查找过程
extern int fib_table_insert(struct fib_table *, struct fib_config *);
extern int fib_table_delete(struct fib_table *, struct fib_config *);
extern int fib_table_dump(struct fib_table *table, struct sk_buff *skb, struct netlink_callback *cb); // 路由转发
extern int fib_table_flush(struct fib_table *table); // 移除路由信息结构
extern void fib_free_table(struct fib_table *tb);



#ifndef CONFIG_IP_MULTIPLE_TABLES

#define TABLE_LOCAL_INDEX	0
#define TABLE_MAIN_INDEX	1

static inline struct fib_table *fib_get_table(struct net *net, u32 id)
{
    struct hlist_head *ptr;

    ptr = id == RT_TABLE_LOCAL ?
          &net->ipv4.fib_table_hash[TABLE_LOCAL_INDEX] :
          &net->ipv4.fib_table_hash[TABLE_MAIN_INDEX];
    return hlist_entry(ptr->first, struct fib_table, tb_hlist);
}

static inline struct fib_table *fib_new_table(struct net *net, u32 id)
{
    return fib_get_table(net, id);
}

static inline int fib_lookup(struct net *net, const struct flowi4 *flp, // 没有开启多路径路由
                             struct fib_result *res)
{
    struct fib_table *table;

    table = fib_get_table(net, RT_TABLE_LOCAL);
    if (!fib_table_lookup(table, flp, res, FIB_LOOKUP_NOREF))
        return 0;

    table = fib_get_table(net, RT_TABLE_MAIN);
    if (!fib_table_lookup(table, flp, res, FIB_LOOKUP_NOREF))
        return 0;
    return -ENETUNREACH;
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
extern int __net_init fib4_rules_init(struct net *net);
extern void __net_exit fib4_rules_exit(struct net *net);

#ifdef CONFIG_IP_ROUTE_CLASSID
extern u32 fib_rules_tclass(const struct fib_result *res);
#endif

extern int fib_lookup(struct net *n, struct flowi4 *flp, struct fib_result *res);

extern struct fib_table *fib_new_table(struct net *net, u32 id);
extern struct fib_table *fib_get_table(struct net *net, u32 id);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern const struct nla_policy rtm_ipv4_policy[];
extern void		ip_fib_init(void);
extern int fib_validate_source(struct sk_buff *skb, __be32 src, __be32 dst,
                               u8 tos, int oif, struct net_device *dev,
                               __be32 *spec_dst, u32 *itag);
extern void fib_select_default(struct fib_result *res);

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(__be32 gw, struct net_device *dev);
extern int fib_sync_down_dev(struct net_device *dev, int force);
extern int fib_sync_down_addr(struct net *net, __be32 local);
extern void fib_update_nh_saddrs(struct net_device *dev);
extern int fib_sync_up(struct net_device *dev);
extern void fib_select_multipath(struct fib_result *res);

/* Exported by fib_trie.c */
extern void fib_trie_init(void);
extern struct fib_table *fib_trie_table(u32 id);

static inline void fib_combine_itag(u32 *itag, const struct fib_result *res)
{
#ifdef CONFIG_IP_ROUTE_CLASSID
#ifdef CONFIG_IP_MULTIPLE_TABLES
    u32 rtag;
#endif
    *itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
    rtag = fib_rules_tclass(res);
    if (*itag == 0)
        *itag = (rtag<<16);
    *itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
    if (atomic_dec_and_test(&fi->fib_clntref))
        free_fib_info(fi);
}

#ifdef CONFIG_PROC_FS
extern int __net_init  fib_proc_init(struct net *net);
extern void __net_exit fib_proc_exit(struct net *net);
#else
static inline int fib_proc_init(struct net *net)
{
    return 0;
}
static inline void fib_proc_exit(struct net *net)
{
}
#endif

#endif  /* _NET_FIB_H */
