#include <bits/pthreadtypes.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>

// 下面一行是自己加的，用于kmalloc
#include <linu/slab.h>
#include <pthread.h>

#include <linux/vmalloc.h>
#include <linux/kdev_t.h>
#include "dm-dedup-target.h"
#include "dm-dedup-rw.h"
#include "dm-dedup-hash.h"
#include "dm-dedup-backend.h"
#include "dm-dedup-ram.h"
#include "dm-dedup-cbt.h"
#include "dm-dedup-kvstore.h"
#include "dm-dedup-check.h"

#define HASH_LBN 0
#define HASH_NOLBN 1
#define NOHASH_LBN 3
#define NOHASH_NOLBN 4

static struct task_struct *hash_thread;
static struct task_struct *lookup_thread;
static struct task_struct *process_thread;

static struct lookup_queue_bio {
    struct list_head node;
    struct bio *bio;
    u8* hash; // hash
};

static struct process_queue_bio {
    struct list_head node;
    struct bio *bio;
    struct hash_pbn_value hash2pbn_value;
    struct lbn_pbn_value lbn2pbn_value;
    u8* hash;
    int result; // 查表结果
};

static struct bio_queue {
    struct list_head queue;  // bio请求队列
    spinlock_t lock;         // 自旋锁，用于对队列进行保护
};

static struct bio_queue lookup_queue;  // 查表队列
static struct bio_queue process_queue; // 处理程序队列

static u8* calculate_hash(struct dedup_config *dc, struct bio *bio)
{
    // 求hash的处理逻辑
    // 分配hash的存储空间
    u8* hash = kmalloc(sizeof(u8) * MAX_DIGEST_SIZE, GFP_KERNEL);
    if(hash == NULL) {
        printk(KERN_INFO "Memory allocation failed\n");
        return NULL;
    }
    int r;
    compute_hash_bio(dc->desc_table, bio, hash);
    return hash;
}

int task_completed = 0; // 标志两个线程完成
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; // 互斥锁，保护对上面标志的并发访问

struct ThreadArgs {
    struct dedup_config *dc;
    struct bio *bio;
    u8 *hash;
    struct hash_pbn_value *hash2pbn_value;
    struct lbn_pbn_value *lbn2pbn_value;
    int *r;
};

static void lookup_hash_pbn(struct dedup_config *dc, struct bio *bio, u8 *hash, 
                        struct hash_pbn_value *hash2pbn_value, 
                        struct lbn_pbn_value *lbn2pbn_value,
                        int *r1) 
{
    u64 lbn = bio_lbn(dc, bio); // bio的lbn
    r1 = dc->kvs_hash_pbn->kvs_lookup(dc->kvs_hash_pbn, hash,
                dc->crypto_key_size,
                &hash2pbn_value, &vsize);

    pthread_mutex_lock(&mutex);
    task_completed++;
    pthread_mutex_unlock(&mutex);
}

static void lookup_lbn_pbn(struct dedup_config *dc, struct bio *bio, u8 *hash, 
                        struct hash_pbn_value *hash2pbn_value, 
                        struct lbn_pbn_value *lbn2pbn_value, 
                        int *r2) 
{
    u64 lbn = bio_lbn(dc, bio); // bio的lbn
    r2 = dc->kvs_lbn_pbn->kvs_lookup(dc->kvs_lbn_pbn, (void *)&lbn,
					sizeof(lbn), (void *)&lbn2pbn_value,
					&vsize);

    pthread_mutex_lock(&mutex);
    task_completed++;
    pthread_mutex_unlock(&mutex);
}

static int lookup_table(struct dedup_config *dc, struct bio *bio, u8 *hash, 
                        struct hash_pbn_value *hash2pbn_value, 
                        struct lbn_pbn_value *lbn2pbn_value)
{
    // 查表的处理逻辑
    task_completed = 0;
    pthread_t thread1, thread2;
    int r1, r2;
    struct ThreadArgs args1;
    args1.dc = dc;
    args1.bio = bio;
    args1.hash = hash;
    args1.hash2pbn_value = hash2pbn_value;
    args1.lbn2pbn_value = lbn2pbn_value;
    args1.r = r1;
    struct ThreadArgs args2 = args1;
    args2.r = r2;
    pthread_create(&thread1, NULL, lookup_hash_pbn, (void*)args1);
    pthread_create(&thread2, NULL, lookup_lbn_pbn, NULL);

    while(1) {
        pthread_mutex_lock(&mutex);
        if(task_completed == 2) {
            pthread_mutex_unlock(&mutex);
            break;
        }
        pthread_mutex_unlock(&mutex);
    }

    // 等待两个线程结束
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    if(r1 == -ENODATA) {
        // hash -> pbn not found
        if(r2 == -ENODATA) {
            // lbn -> pbn not found
            result = NOHASH_NOLBN;
        }
        else {
            // lbn -> pbn found
            result = NOHASH_LBN;
        }
    }
    else {
        // hash -> pbn found
        if(r2 == -ENODATA) {
            // lbn -> pbn not found
            result = HASH_LBN;
        }
        else {
            // lbn -> pbn found
            result = HASH_NOLBN;
        }
    }
    return result;
}

static void process_data(struct dedup_config *dc, struct process_queue_bio process_queue_bio)
{
    // 处理程序的逻辑
    switch (process_queue_bio.result) {
    case HASH_LBN:
        __handle_has_lbn_pbn_with_hash(dc, process_queue_bio.bio, 
                                    bio_lbn(dc, process_queue_bio.bio), 
                                    process_queue_bio.hash2pbn_value.pbn,
						            process_queue_bio.lbn2pbn_value);
        dc->dupwrites++;
    case HASH_NOLBN:
        __handle_no_lbn_pbn_with_hash(dc, process_queue_bio.bio,
                                    bio_lbn(dc, process_queue_bio.bio), 
                                    process_queue_bio.hash2pbn_value.pbn,
						            process_queue_bio.lbn2pbn_value);
    case NOHASH_LBN:
		__handle_has_lbn_pbn(dc, process_queue_bio.bio,
                            bio_lbn(dc, process_queue_bio.bio), 
                            process_queue_bio.hash, 
                            process_queue_bio.lbn2pbn_value.pbn);
        dc->dupwrites++;
    case NOHASH_NOLBN:
        __handle_no_lbn_pbn(dc, process_queue_bio.bio,
                            io_lbn(dc, process_queue_bio.bio), 
                            process_queue_bio.hash);
    }
    free(process_queue_bio.hash)
}

static void add_to_lookup_queue(struct bio *bio, u8* hash)
{
    spin_lock(&lookup_queue.lock);  // 获取自旋锁

    // 将bio添加到查表队列
    struct lookup_queue_bio lookup_queue_bio;
    lookup_queue_bio.bio = bio;
    lookup_queue_bio.hash = hash;
    
    list_add_tail(&lookup_queue_bio.node, &lookup_queue.queue);

    spin_unlock(&lookup_queue.lock);  // 释放自旋锁
}

static void add_to_process_queue(struct bio *bio, int result, 
                                struct hash_pbn_value hash2pbn_value, 
                                struct lbn_pbn_value lbn2pbn_value)
{
    spin_lock(&process_queue.lock);  // 获取自旋锁

    // 将bio添加到处理程序队列
    struct process_queue_bio process_queue_bio;
    process_queue_bio.bio = bio;
    process_queue_bio.result = result;
    process_queue_bio.hash2pbn_value = hash2pbn_value;
    process_queue_bio.lbn2pbn_value = lbn2pbn_value;
    list_add_tail(&process_queue_bio.node, &process_queue.queue);

    spin_unlock(&process_queue.lock);  // 释放自旋锁
}

static struct lookup_queue_bio *get_next_bio_from_lookup_queue(struct bio_queue *queue)
{
    struct lookup_queue_bio *lookup_queue_bio = NULL;

    spin_lock(&queue->lock);  // 获取自旋锁

    if (!list_empty(&queue->queue)) {
        // 从队列中获取下一个bio请求
        struct list_head *entry = queue->queue.next;
        lookup_queue_bio = list_entry(entry, struct bio, list_node);
        list_del(entry);
    }

    spin_unlock(&queue->lock);  // 释放自旋锁

    return lookup_queue_bio;
}

static struct process_queue_bio *get_next_bio_from_process_queue(struct bio_queue *queue)
{
    struct process_queue_bio *process_queue_bio = NULL;

    spin_lock(&queue->lock);  // 获取自旋锁

    if (!list_empty(&queue->queue)) {
        // 从队列中获取下一个bio请求
        struct list_head *entry = queue->queue.next;
        process_queue_bio = list_entry(entry, struct bio, list_node);
        list_del(entry);
    }

    spin_unlock(&queue->lock);  // 释放自旋锁

    return process_queue_bio;
}

static int hash_func(void *data)
{
    while (!kthread_should_stop()) {
        struct bio *bio = get_next_bio(&bio_queue);

        if (bio) {
            // 求hash的处理逻辑
            u8 *hash;
            hash = calculate_hash(bio);

            // 将bio传递给下一个阶段
            add_to_lookup_queue(bio, hash);
        }
    }

    return 0;
}

static int lookup_func(void *data)
{
    while (!kthread_should_stop()) {
        struct lookup_queue_bio *lookup_queue_bio = get_next_bio_from_lookup_queue(&lookup_queue);
        if (lookup_queue_bio) {
            // 查表的处理逻辑
            int result;
            struct hash_pbn_value hash2pbn_value;
            struct lbn_pbn_value lbn2pbn_value
            result = lookup_table(lookup_queue_bio->bio, lookup_queue_bio->hash, 
                                &hash2pbn_value, &lbn2pbn_value);

            // 将bio传递给下一个阶段
            add_to_process_queue(lookup_queue_bio->bio, result, hash2pbn_value, lbn2pbn_value);
        }
    }

    return 0;
}

static int process_func(void *data)
{
    while (!kthread_should_stop()) {
        // struct bio *bio = get_next_bio(&process_queue);
        struct process_queue_bio *process_queue_bio = get_next_bio_from_process_queue(&process_queue);

        if (bio) {
            // 处理程序的逻辑
            process_data(process_queue_bio);

        }
    }

    return 0;
}

static int __init pipeline_init(void)
{
    printk(KERN_INFO "Pipeline module initialized\n");

    // 初始化bio请求队列和自旋锁
    INIT_LIST_HEAD(&bio_queue.queue);
    spin_lock_init(&bio_queue.lock);
    INIT_LIST_HEAD(&lookup_queue.queue);
    spin_lock_init(&lookup_queue.lock);
    INIT_LIST_HEAD(&process_queue.queue);
    spin_lock_init(&process_queue.lock);

    // 创建流水线阶段线程
    hash_thread = kthread_run(hash_func, NULL, "hash_thread");
    lookup_thread = kthread_run(lookup_func, NULL, "lookup_thread");
    process_thread = kthread_run(process_func, NULL, "process_thread");

    return 0;
}

static void __exit pipeline_exit(void)
{
    // 停止并清理流水线阶段线程
    kthread_stop(hash_thread);
    kthread_stop(lookup_thread);
    kthread_stop(process_thread);

    printk(KERN_INFO "Pipeline module exited\n");
}

module_init(pipeline_init);
module_exit(pipeline_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Example pipeline module");
