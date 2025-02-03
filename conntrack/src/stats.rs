use netlink_packet_netfilter::ctnetlink::nlas::stat::nla::StatNla;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Stats {
    pub cpu: u16,
    pub searched: Option<u32>, // no longer used
    pub found: u32,
    pub new: Option<u32>, // no longer used
    pub invalid: u32,
    pub ignore: Option<u32>,      // no longer used
    pub delete: Option<u32>,      // no longer used
    pub delete_list: Option<u32>, // no longer used
    pub insert: u32,
    pub insert_failed: u32,
    pub drop: u32,
    pub early_drop: u32,
    pub error: u32,
    pub search_restart: u32,
    pub clash_resolve: u32,
    pub chain_too_long: u32,
}

/*
    // ref: conntrack-tools/src/conntrack.c

   const char *attr2name[CTA_STATS_MAX + UNKNOWN_STATS_NUM + 1] = {
       [CTA_STATS_SEARCHED]	= "searched", // 1
       [CTA_STATS_FOUND]	= "found", // 2
       [CTA_STATS_NEW]		= "new", // 3
       [CTA_STATS_INVALID]	= "invalid",
       [CTA_STATS_IGNORE]	= "ignore",
       [CTA_STATS_DELETE]	= "delete",
       [CTA_STATS_DELETE_LIST]	= "delete_list",
       [CTA_STATS_INSERT]	= "insert",
       [CTA_STATS_INSERT_FAILED] = "insert_failed",
       [CTA_STATS_DROP]	= "drop",
       [CTA_STATS_EARLY_DROP]	= "early_drop",
       [CTA_STATS_ERROR]	= "error",
       [CTA_STATS_SEARCH_RESTART] = "search_restart",
       [CTA_STATS_CLASH_RESOLVE] = "clash_resolve",
       [CTA_STATS_CHAIN_TOOLONG] = "chaintoolong",

       /* leave at end.  Allows to show counters supported
        * by newer kernel with older conntrack-tools release.
        */
       [CTA_STATS_MAX + 1] = "unknown1",
       [CTA_STATS_MAX + 2] = "unknown2",
       [CTA_STATS_MAX + 3] = "unknown3",
       [CTA_STATS_MAX + 4] = "unknown4",
   };

   static int nfct_stats_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, CTA_STATS_MAX + UNKNOWN_STATS_NUM) < 0)
        return MNL_CB_OK;

    if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
        perror("mnl_attr_validate");
        return MNL_CB_ERROR;
    }

    tb[type] = attr;
    return MNL_CB_OK;
}

// ref: https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink_conntrack.h

enum ctattr_stats_cpu {
    CTA_STATS_UNSPEC,
    CTA_STATS_SEARCHED,	/* no longer used */
    CTA_STATS_FOUND,
    CTA_STATS_NEW,		/* no longer used */
    CTA_STATS_INVALID,
    CTA_STATS_IGNORE,	/* no longer used */
    CTA_STATS_DELETE,	/* no longer used */
    CTA_STATS_DELETE_LIST,	/* no longer used */
    CTA_STATS_INSERT,
    CTA_STATS_INSERT_FAILED,
    CTA_STATS_DROP,
    CTA_STATS_EARLY_DROP,
    CTA_STATS_ERROR,
    CTA_STATS_SEARCH_RESTART,
    CTA_STATS_CLASH_RESOLVE,
    CTA_STATS_CHAIN_TOOLONG,
    __CTA_STATS_MAX,
};
#define CTA_STATS_MAX (__CTA_STATS_MAX - 1)
*/

impl Stats {
    pub(super) fn from_nlas(cpu: u16, nlas: &[StatNla]) -> Stats {
        let mut stats = Stats {
            cpu,
            ..Default::default()
        };

        for nla in nlas.iter() {
            match &nla {
                StatNla::Searched(_v) => stats.searched = None, // no longer used
                StatNla::Found(v) => stats.found = *v,
                StatNla::New(_v) => stats.new = None, // no longer used
                StatNla::Invalid(v) => stats.invalid = *v,
                StatNla::Ignore(_v) => stats.ignore = None, // no longer used
                StatNla::Delete(_v) => stats.delete = None, // no longer used
                StatNla::DeleteList(_v) => stats.delete_list = None, // no longer used
                StatNla::Insert(v) => stats.insert = *v,
                StatNla::InsertFailed(v) => stats.insert_failed = *v,
                StatNla::Drop(v) => stats.drop = *v,
                StatNla::EarlyDrop(v) => stats.early_drop = *v,
                StatNla::Error(v) => stats.error = *v,
                StatNla::SearchRestart(v) => stats.search_restart = *v,
                StatNla::ClashResolve(v) => stats.clash_resolve = *v,
                StatNla::ChainTooLong(v) => stats.chain_too_long = *v,
                StatNla::Other(_) => {
                    continue;
                }
            }
        }

        stats
    }
}
