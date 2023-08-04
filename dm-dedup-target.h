/*
 * Copyright (C) 2012-2017 Vasily Tarasov
 * Copyright (C) 2012-2014 Geoff Kuenning
 * Copyright (C) 2012-2014 Sonam Mandal
 * Copyright (C) 2012-2014 Karthikeyani Palanisami
 * Copyright (C) 2012-2014 Philip Shilane
 * Copyright (C) 2012-2014 Sagar Trehan
 * Copyright (C) 2012-2017 Erez Zadok
 * Copyright (c) 2016-2017 Vinothkumar Raja
 * Copyright (c) 2017-2017 Nidhi Panpalia
 * Copyright (c) 2012-2017 Stony Brook University
 * Copyright (c) 2012-2017 The Research Foundation for SUNY
 * This file is released under the GPL.
 */

#ifndef DM_DEDUP_H
#define DM_DEDUP_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/list.h>
#include <linux/err.h>
#include <asm/current.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/parser.h>
#include <linux/blk_types.h>
#include <linux/mempool.h>

#include <linux/scatterlist.h>
#include <asm/page.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/sha.h>
#include <crypto/algapi.h>

#include <linux/kthread.h>
#include <linux/mutex.h>



#define DM_MSG_PREFIX "dedup-mod"

#define CRYPTO_ALG_NAME_LEN     16
#define MAX_DIGEST_SIZE	SHA256_DIGEST_SIZE

#define MAX_BACKEND_NAME_LEN (64)

#define MIN_DEDUP_WORK_IO	16

#define MAX_QUEUE_SIZE   10000

struct bio_queue {
	void *data[MAX_QUEUE_SIZE];
	int front;
	int rear;
    spinlock_t lock;         // 自旋锁，用于对队列进行保护
};

/* Per target instance structure */
struct dedup_config {
	// 数据设备和元数据设备的指针
	struct dm_dev *data_dev;
	struct dm_dev *metadata_dev;

	u32 block_size;	/* in bytes 块大小 */
	u32 sectors_per_block; // 每个块的扇区数

	u32 pblocks;	/* physical blocks 物理块数 */
	u32 lblocks;	/* logical blocks  逻辑块数*/

	struct workqueue_struct *workqueue; // 工作队列结构体指针

	struct bio_set bs;
	struct hash_desc_table *desc_table;

	u64 logical_block_counter;	/* 已使用的逻辑块总数 */
	u64 physical_block_counter;/* 已使用的物理块总数 */
	u64 gc_counter; /* 垃圾回收的块总数 */

	u64	writes;		/* 总写入次数 */
	u64	dupwrites; // 重复数据写入次数
	u64	uniqwrites; // 唯一数据写入次数
	u64	reads_on_writes; // 写入时进行的读取次数
	u64	overwrites;	/* writes to a prev. written offset */
	u64	newwrites;	/* writes to never written offsets */

	/* flag to check for data corruption */
	bool	check_corruption;
	bool	fec;		/* flag to fix block corruption */
	u64	fec_fixed;	/* number of corruptions fixed */
	/* Total number of corruptions encountered */
	u64	corrupted_blocks;

	/* used for read-on-write of misaligned requests */
	struct dm_io_client *io_client;

	char backend_str[MAX_BACKEND_NAME_LEN];
	struct metadata_ops *mdops;
	struct metadata *bmd;
	struct kvstore *kvs_hash_pbn; // hash -> pbn表
	struct kvstore *kvs_lbn_pbn; // lbn -> pbn表

	char crypto_alg[CRYPTO_ALG_NAME_LEN]; // 加密算法名称
	int crypto_key_size; //加密秘钥大小(指纹大小)

	u32 flushrq;		/* after how many writes call flush */
	u64 writes_after_flush;	/* # of writes after the last flush */

	mempool_t *dedup_work_pool;	/* Dedup work pool */
	mempool_t *check_work_pool;	/* Corruption check work pool */

	// -----------------------pipeline-----------------------------------------
	struct task_struct *hash_thread; // Compute hash thread
	struct task_struct *lookup_thread; // lookup thread
	struct task_struct *process_thread; // process thread

	struct bio_queue hash_queue; // 计算指纹队列
	struct bio_queue lookup_queue;  // 查表队列
	struct bio_queue process_queue; // 处理程序队列
	int task_completed; // 标志两个线程完成
	struct mutex my_mutex; // 互斥锁，保护对上面标志的并发访问
};

/* Value of the HASH-PBN key-value store */
struct hash_pbn_value {
	u64 pbn;	/* in blocks */
};

/* Value of the LBN-PBN key-value store */
struct lbn_pbn_value {
	u64 pbn;	/* in blocks */
};

// -----------------------------------------------------------------------------

struct hash_queue_bio {
	struct bio *bio;
	int status;
};

struct lookup_queue_bio { // compute_hash ---queue--- lookup
    struct bio *bio;
    u8* hash; // hash
	int status;
};

struct process_queue_bio { // lookup ---queue--- process
    struct bio *bio;
    struct hash_pbn_value hash2pbn_value;
    struct lbn_pbn_value lbn2pbn_value;
    u8* hash;
    int result; // 查表结果
	int status;
};

struct ThreadArgs {
    struct dedup_config *dc;
    struct bio *bio;
    u8 *hash;
    struct hash_pbn_value *hash2pbn_value;
    struct lbn_pbn_value *lbn2pbn_value;
    int *r;
};


#endif /* DM_DEDUP_H */
