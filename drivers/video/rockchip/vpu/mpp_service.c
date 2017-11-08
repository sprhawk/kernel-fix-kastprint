/**
 * Copyright (C) 2016 - 2017 Fuzhou Rockchip Electronics Co., Ltd
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/slab.h>

#include "mpp_dev_common.h"
#include "mpp_service.h"

struct mpp_service {
	/* serivce critical time lock */
	struct mutex running_lock;
	struct list_head running;

	u32 dev_cnt;
	struct list_head subdev_list;
};

struct mpp_service_node {
	/* node structure global lock */
	struct mutex lock;
	struct mpp_service *parent;
	struct list_head pending;
};

/* service queue schedule */
void mpp_srv_push_pending(struct mpp_service_node *node, struct mpp_task *task)
{
	mutex_lock(&node->lock);

	list_add_tail(&task->session_link, &task->session->pending);
	list_add_tail(&task->status_link, &node->pending);

	mutex_unlock(&node->lock);
}
EXPORT_SYMBOL(mpp_srv_push_pending);

struct mpp_task *mpp_srv_get_pending_task(struct mpp_service_node *node)
{
	struct mpp_task *task = NULL;

	mutex_lock(&node->lock);
	if (!list_empty(&node->pending)) {
		task = list_first_entry(&node->pending, struct mpp_task,
					status_link);
		list_del_init(&task->status_link);
	}
	mutex_unlock(&node->lock);

	return task;
}
EXPORT_SYMBOL(mpp_srv_get_pending_task);

int mpp_srv_is_running(struct mpp_service_node *node)
{
	struct mpp_service *pservice = node->parent;

	return mutex_trylock(&pservice->running_lock);
}
EXPORT_SYMBOL(mpp_srv_is_running);

void mpp_srv_wait_to_run(struct mpp_service_node *node)
{
	struct mpp_service *pservice = node->parent;

	mutex_lock(&pservice->running_lock);
}
EXPORT_SYMBOL(mpp_srv_wait_to_run);

struct mpp_task *mpp_srv_get_current_task(struct mpp_service_node *node)
{
	struct mpp_service *pservice = node->parent;

	return list_first_entry(&pservice->running, struct mpp_task,
				status_link);
}
EXPORT_SYMBOL(mpp_srv_get_current_task);

/* mpp_srv_wait_to_run() will lock this link list */
void mpp_srv_run(struct mpp_service_node *node, struct mpp_task *task)
{
	struct mpp_service *pservice = node->parent;

	list_add_tail(&task->status_link, &pservice->running);
}
EXPORT_SYMBOL(mpp_srv_run);

void mpp_srv_done(struct mpp_service_node *node, struct mpp_task *task)
{
	struct mpp_service *pservice = node->parent;

	list_del(&task->status_link);
	list_del_init(&task->session_link);
	mutex_unlock(&pservice->running_lock);

	mutex_lock(&node->lock);
	list_add_tail(&task->session_link, &task->session->done);
	mutex_unlock(&node->lock);

	wake_up(&task->session->wait);
}
EXPORT_SYMBOL(mpp_srv_done);

int mpp_srv_abort(struct mpp_service_node *node, struct mpp_task *task)
{
	struct mpp_service *pservice = node->parent;

	if (task) {
		list_del(&task->status_link);
		list_del(&task->session_link);
	}
	/* The lock is acquired by is_running() or run() */
	mutex_unlock(&pservice->running_lock);

	return 0;
}
EXPORT_SYMBOL(mpp_srv_abort);

struct mpp_task *mpp_srv_get_done_task(struct mpp_service_node *node,
				       struct mpp_session *session)
{
	struct mpp_task *task = NULL;

	mutex_lock(&node->lock);
	if (!list_empty(&session->done)) {
		task = list_first_entry(&session->done,
					struct mpp_task, session_link);
		list_del(&task->session_link);
	}
	mutex_unlock(&node->lock);
	return task;
}
EXPORT_SYMBOL(mpp_srv_get_done_task);

void *mpp_srv_attach(struct mpp_service *pservice, void *data)
{
	struct mpp_service_node *node = NULL;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return node;

	node->parent = pservice;
	mutex_init(&node->lock);
	INIT_LIST_HEAD(&node->pending);

	return node;
}
EXPORT_SYMBOL(mpp_srv_attach);

void mpp_srv_detach(struct mpp_service_node *node)
{
	kfree(node);
}
EXPORT_SYMBOL(mpp_srv_detach);

static void mpp_init_drvdata(struct mpp_service *pservice)
{
	mutex_init(&pservice->running_lock);
	INIT_LIST_HEAD(&pservice->running);
}

static int mpp_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mpp_service *pservice = devm_kzalloc(dev, sizeof(*pservice),
						    GFP_KERNEL);
	if (!pservice)
		return -ENOMEM;

	mpp_init_drvdata(pservice);

	platform_set_drvdata(pdev, pservice);
	dev_info(dev, "init success\n");

	return 0;
}

static int mpp_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id mpp_service_dt_ids[] = {
	{ .compatible = "rockchip,mpp-service", },
	{ },
};

static struct platform_driver mpp_driver = {
	.probe = mpp_probe,
	.remove = mpp_remove,
	.driver = {
		.name = "mpp",
		.of_match_table = of_match_ptr(mpp_service_dt_ids),
	},
};

static int __init mpp_service_init(void)
{
	int ret = platform_driver_register(&mpp_driver);

	if (ret) {
		pr_err("Platform device register failed (%d).\n", ret);
		return ret;
	}

	return ret;
}

static void __exit mpp_service_exit(void)
{
}

module_init(mpp_service_init);
module_exit(mpp_service_exit)
MODULE_LICENSE("GPL");
