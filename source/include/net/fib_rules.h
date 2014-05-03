#ifndef __NET_FIB_RULES_H
#define __NET_FIB_RULES_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/fib_rules.h>
#include <net/flow.h>
#include <net/rtnetlink.h>

struct fib_rule {
    struct list_head	list;
    atomic_t		refcnt;
    int			iifindex;
    int			oifindex;
    u32			mark;
    u32			mark_mask;
    u32			pref;
    u32			flags;
    u32			table;
    u8			action;
    u32			target;
    struct fib_rule __rcu	*ctarget;
    char			iifname[IFNAMSIZ];
    char			oifname[IFNAMSIZ];
    struct rcu_head		rcu;
    struct net *		fr_net;
};

struct fib_lookup_arg {
    void			*lookup_ptr;
    void			*result;
    struct fib_rule		*rule;
    int			flags;
#define FIB_LOOKUP_NOREF	1
};

struct fib_rules_ops {
    int			family;  // 协议族ID
    struct list_head	list;  // 队列头，用于链入网络空间的队列中
    int			rule_size;    // 规则结构长度
    int			addr_size;   // 地址长度
    int			unresolved_rules;
    int			nr_goto_rules;

    int			(*action)(struct fib_rule *, // 动作函数指针
                          struct flowi *, int, struct fib_lookup_arg *);
    int			(*match)(struct fib_rule *, struct flowi *, int); // 匹配函数指针
    int			(*configure)(struct fib_rule *,  // 配置函数指针
                             struct sk_buff *, struct fib_rule_hdr *, struct nlattr **);
    int			(*compare)(struct fib_rule *,  // 对比函数指针
                           struct fib_rule_hdr *,struct nlattr **);
    int			(*fill)(struct fib_rule *,  // 填写函数指针
                        struct sk_buff *, struct fib_rule_hdr *);
    u32			(*default_pref)(struct fib_rules_ops *ops); // 查找优先级函数指针
    size_t			(*nlmsg_payload)(struct fib_rule *); // 统计负载数据能力函数指针

    /* Called after modifications to the rules set, must flush
     * the route cache if one exists. */
    void			(*flush_cache)(struct fib_rules_ops *ops); //修改规则队列后，必须刷新缓存的函数指针

    int			nlgroup;  // 路由netlink的划分标识
    const struct nla_policy	*policy; // netlink 的属性优先级
    struct list_head	rules_list;  // 路由规则队列
    struct module		*owner;
    struct net		*fro_net;  // 网络空间结构指针
    struct rcu_head		rcu;
};

#define FRA_GENERIC_POLICY \
	[FRA_IIFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_OIFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_PRIORITY]	= { .type = NLA_U32 }, \
	[FRA_FWMARK]	= { .type = NLA_U32 }, \
	[FRA_FWMASK]	= { .type = NLA_U32 }, \
	[FRA_TABLE]     = { .type = NLA_U32 }, \
	[FRA_GOTO]	= { .type = NLA_U32 }

static inline void fib_rule_get(struct fib_rule *rule)
{
    atomic_inc(&rule->refcnt);
}

static inline void fib_rule_put_rcu(struct rcu_head *head)
{
    struct fib_rule *rule = container_of(head, struct fib_rule, rcu);
    release_net(rule->fr_net);
    kfree(rule);
}

static inline void fib_rule_put(struct fib_rule *rule)
{
    if (atomic_dec_and_test(&rule->refcnt))
        call_rcu(&rule->rcu, fib_rule_put_rcu);
}

static inline u32 frh_get_table(struct fib_rule_hdr *frh, struct nlattr **nla)
{
    if (nla[FRA_TABLE])
        return nla_get_u32(nla[FRA_TABLE]);
    return frh->table;
}

extern struct fib_rules_ops *fib_rules_register(const struct fib_rules_ops *, struct net *);
extern void fib_rules_unregister(struct fib_rules_ops *);

extern int			fib_rules_lookup(struct fib_rules_ops *,
                                     struct flowi *, int flags,
                                     struct fib_lookup_arg *);
extern int			fib_default_rule_add(struct fib_rules_ops *,
        u32 pref, u32 table,
        u32 flags);
extern u32			fib_default_rule_pref(struct fib_rules_ops *ops);
#endif
