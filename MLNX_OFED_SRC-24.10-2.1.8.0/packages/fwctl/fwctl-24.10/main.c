// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "fwctl: " fmt
#include <linux/fwctl.h>
#include <linux/module.h>
#include <linux/slab.h>
#ifdef HAVE_CONTAINER_OF_H
#include <linux/container_of.h>
#endif
#include <linux/fs.h>
#include <linux/sizes.h>
#if !defined(HAVE_CONTAINER_OF_H) || !defined(HAVE_PANIC_H)
#include <linux/kernel.h>
#endif
#ifndef HAVE_KVFREE_IN_SLAB_H
#include <linux/mm.h>
#endif
#ifndef HAVE_CHECK_ZEROED_USER
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/nospec.h>
#endif
#include <uapi/fwctl/fwctl.h>

enum {
	FWCTL_MAX_DEVICES = 4096,
	MAX_RPC_LEN = SZ_2M,
};
static dev_t fwctl_dev;
static DEFINE_IDA(fwctl_ida);
static unsigned long fwctl_tainted;

DEFINE_FREE(kfree_errptr, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T));
DEFINE_FREE(kvfree_errptr, void *, if (!IS_ERR_OR_NULL(_T)) kvfree(_T));
DEFINE_FREE(kvfree_wrapper, void *, kvfree(_T));

#ifndef HAVE_CLEANUP_H
/* from include/linux/slab.h, added in upstream 6.5 */
DEFINE_FREE(kfree, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T))

/* from include/linux/rwsem.h, added in upstream 6.5 */
DEFINE_GUARD(rwsem_read, struct rw_semaphore *, down_read(_T), up_read(_T))
DEFINE_GUARD(rwsem_write, struct rw_semaphore *, down_write(_T), up_write(_T))

/* from include/linux/mutex.h, added in upstream 6.5 */
DEFINE_GUARD(mutex, struct mutex *, mutex_lock(_T), mutex_unlock(_T))
#endif

struct fwctl_ucmd {
	struct fwctl_uctx *uctx;
	void __user *ubuffer;
	void *cmd;
	u32 user_size;
};

static int ucmd_respond(struct fwctl_ucmd *ucmd, size_t cmd_len)
{
	if (copy_to_user(ucmd->ubuffer, ucmd->cmd,
			 min_t(size_t, ucmd->user_size, cmd_len)))
		return -EFAULT;
	return 0;
}

static int copy_to_user_zero_pad(void __user *to, const void *from,
				 size_t from_len, size_t user_len)
{
	size_t copy_len;

	copy_len = min(from_len, user_len);
	if (copy_to_user(to, from, copy_len))
		return -EFAULT;
	if (copy_len < user_len) {
		if (clear_user(to + copy_len, user_len - copy_len))
			return -EFAULT;
	}
	return 0;
}

static int fwctl_cmd_info(struct fwctl_ucmd *ucmd)
{
	struct fwctl_device *fwctl = ucmd->uctx->fwctl;
	struct fwctl_info *cmd = ucmd->cmd;
	size_t driver_info_len = 0;

	if (cmd->flags)
		return -EOPNOTSUPP;

	if (cmd->device_data_len) {
		void *driver_info __free(kfree_errptr) =
			fwctl->ops->info(ucmd->uctx, &driver_info_len);
		if (IS_ERR(driver_info))
			return PTR_ERR(driver_info);

		if (copy_to_user_zero_pad(u64_to_user_ptr(cmd->out_device_data),
					  driver_info, driver_info_len,
					  cmd->device_data_len))
			return -EFAULT;
	}

	cmd->out_device_type = fwctl->ops->device_type;
	cmd->device_data_len = driver_info_len;
	return ucmd_respond(ucmd, sizeof(*cmd));
}

static int fwctl_cmd_rpc(struct fwctl_ucmd *ucmd)
{
	struct fwctl_device *fwctl = ucmd->uctx->fwctl;
	struct fwctl_rpc *cmd = ucmd->cmd;
	size_t out_len;
#ifdef HAVE_CAN_USE_KVFREE_CLEANUP_NO_WRAPPER
	void *inbuf __free(kvfree) = NULL;
#else
	void *inbuf __free(kvfree_wrapper) = NULL;
#endif
	void *outbuf __free(kvfree_errptr) = NULL;

	if (cmd->in_len > MAX_RPC_LEN || cmd->out_len > MAX_RPC_LEN)
		return -EMSGSIZE;

	switch (cmd->scope) {
	case FWCTL_RPC_CONFIGURATION:
	case FWCTL_RPC_DEBUG_READ_ONLY:
		break;

	case FWCTL_RPC_DEBUG_WRITE_FULL:
		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		fallthrough;
	case FWCTL_RPC_DEBUG_WRITE:
		if (!test_and_set_bit(0, &fwctl_tainted)) {
			dev_warn(
				&fwctl->dev,
				"%s(%d): has requested full access to the physical device device",
				current->comm, task_pid_nr(current));
			add_taint(TAINT_FWCTL, LOCKDEP_STILL_OK);
		}
		break;
	default:
		return -EOPNOTSUPP;
	};

	inbuf = kvzalloc(cmd->in_len, GFP_KERNEL | GFP_KERNEL_ACCOUNT);
	if (!inbuf)
		return -ENOMEM;
	if (copy_from_user(inbuf, u64_to_user_ptr(cmd->in), cmd->in_len))
		return -EFAULT;

	out_len = cmd->out_len;
	outbuf = fwctl->ops->fw_rpc( ucmd->uctx, cmd->scope, inbuf, cmd->in_len, &out_len);
	if (IS_ERR(outbuf))
		return PTR_ERR(outbuf);
	if (outbuf == inbuf) {
		/* The driver can re-use inbuf as outbuf */
		inbuf = NULL;
	}

	if (copy_to_user(u64_to_user_ptr(cmd->out), outbuf,
			 min((size_t)cmd->out_len, out_len)))
		return -EFAULT;

	cmd->out_len = out_len;
	return ucmd_respond(ucmd, sizeof(*cmd));
}

/* On stack memory for the ioctl structs */
union ucmd_buffer {
	struct fwctl_info info;
	struct fwctl_rpc rpc;
};

struct fwctl_ioctl_op {
	unsigned int size;
	unsigned int min_size;
	unsigned int ioctl_num;
	int (*execute)(struct fwctl_ucmd *ucmd);
};

#ifndef HAVE_CHECK_ZEROED_USER
static int backport_check_zeroed_user(const void __user *from, size_t size)
{
	unsigned long val;
	uintptr_t align = (uintptr_t) from % sizeof(unsigned long);

	if (unlikely(size == 0))
		return 1;

	from -= align;
	size += align;

#ifdef HAVE_USER_ACCESS_BEGIN_2_PARAMS
	if (!user_access_begin(from, size))
		return -EFAULT;
#elif defined(HAVE_USER_ACCESS_BEGIN_3_PARAMS)
	if (!user_access_begin(VERIFY_READ, from, size))
		return -EFAULT;
#else
	user_access_begin();
#endif

	unsafe_get_user(val, (unsigned long __user *) from, err_fault);
	if (align)
		val &= ~aligned_byte_mask(align);

	while (size > sizeof(unsigned long)) {
		if (unlikely(val))
			goto done;

		from += sizeof(unsigned long);
		size -= sizeof(unsigned long);

		unsafe_get_user(val, (unsigned long __user *) from, err_fault);
	}

	if (size < sizeof(unsigned long))
		val &= aligned_byte_mask(size);

done:
	user_access_end();
	return (val == 0);
err_fault:
	user_access_end();
	return -EFAULT;
}

static __always_inline __must_check int
copy_struct_from_user(void *dst, size_t ksize, const void __user *src,
		      size_t usize)
{
	size_t size = min(ksize, usize);
	size_t rest = max(ksize, usize) - size;

	/* Double check if ksize is larger than a known object size. */
	if (WARN_ON_ONCE(ksize > __builtin_object_size(dst, 1)))
		return -E2BIG;

	/* Deal with trailing bytes. */
	if (usize < ksize) {
		memset(dst + size, 0, rest);
	} else if (usize > ksize) {
		int ret = backport_check_zeroed_user(src + size, rest);
		if (ret <= 0)
			return ret ?: -E2BIG;
	}
	/* Copy the interoperable parts of the struct. */
	if (copy_from_user(dst, src, size))
		return -EFAULT;
	return 0;
}
#endif

#define IOCTL_OP(_ioctl, _fn, _struct, _last)                         \
	[_IOC_NR(_ioctl) - FWCTL_CMD_BASE] = {                        \
		.size = sizeof(_struct) +                             \
			BUILD_BUG_ON_ZERO(sizeof(union ucmd_buffer) < \
					  sizeof(_struct)),           \
		.min_size = offsetofend(_struct, _last),              \
		.ioctl_num = _ioctl,                                  \
		.execute = _fn,                                       \
	}
static const struct fwctl_ioctl_op fwctl_ioctl_ops[] = {
	IOCTL_OP(FWCTL_INFO, fwctl_cmd_info, struct fwctl_info, out_device_data),
	IOCTL_OP(FWCTL_RPC, fwctl_cmd_rpc, struct fwctl_rpc, out),
};

static long fwctl_fops_ioctl(struct file *filp, unsigned int cmd,
			       unsigned long arg)
{
	struct fwctl_uctx *uctx = filp->private_data;
	const struct fwctl_ioctl_op *op;
	struct fwctl_ucmd ucmd = {};
	union ucmd_buffer buf;
	unsigned int nr;
	int ret;

	nr = _IOC_NR(cmd);
	if ((nr - FWCTL_CMD_BASE) >= ARRAY_SIZE(fwctl_ioctl_ops))
		return -ENOIOCTLCMD;
	op = &fwctl_ioctl_ops[nr - FWCTL_CMD_BASE];
	if (op->ioctl_num != cmd)
		return -ENOIOCTLCMD;

	ucmd.uctx = uctx;
	ucmd.cmd = &buf;
	ucmd.ubuffer = (void __user *)arg;
	ret = get_user(ucmd.user_size, (u32 __user *)ucmd.ubuffer);
	if (ret)
		return ret;

	if (ucmd.user_size < op->min_size)
		return -EINVAL;

	ret = copy_struct_from_user(ucmd.cmd, op->size, ucmd.ubuffer,
				    ucmd.user_size);
	if (ret)
		return ret;

	guard(rwsem_read)(&uctx->fwctl->registration_lock);
	if (!uctx->fwctl->ops)
		return -ENODEV;
	return op->execute(&ucmd);
}

static int fwctl_fops_open(struct inode *inode, struct file *filp)
{
	struct fwctl_device *fwctl =
		container_of(inode->i_cdev, struct fwctl_device, cdev);
	int ret;
	struct fwctl_uctx *uctx __free(kfree) = NULL;

	guard(rwsem_read)(&fwctl->registration_lock);
	if (!fwctl->ops)
		return -ENODEV;

	uctx  = kzalloc(fwctl->ops->uctx_size, GFP_KERNEL | GFP_KERNEL_ACCOUNT);
	if (!uctx)
		return -ENOMEM;

	uctx->fwctl = fwctl;
	ret = fwctl->ops->open_uctx(uctx);
	if (ret)
		return ret;

	scoped_guard(mutex, &fwctl->uctx_list_lock) {
		list_add_tail(&uctx->uctx_list_entry, &fwctl->uctx_list);
	}

	get_device(&fwctl->dev);
#ifdef HAVE_AUTO_TYPE
	filp->private_data = no_free_ptr(uctx);
#else
	filp->private_data = uctx;
	uctx = NULL;
#endif

	return 0;
}

static void fwctl_destroy_uctx(struct fwctl_uctx *uctx)
{
	lockdep_assert_held(&uctx->fwctl->uctx_list_lock);
	list_del(&uctx->uctx_list_entry);
	uctx->fwctl->ops->close_uctx(uctx);
}

static int fwctl_fops_release(struct inode *inode, struct file *filp)
{
	struct fwctl_uctx *uctx = filp->private_data;
	struct fwctl_device *fwctl = uctx->fwctl;

	scoped_guard(rwsem_read, &fwctl->registration_lock) {
		if (fwctl->ops) {
			guard(mutex)(&fwctl->uctx_list_lock);
			fwctl_destroy_uctx(uctx);
		}
	}

	kfree(uctx);
	fwctl_put(fwctl);
	return 0;
}

static const struct file_operations fwctl_fops = {
	.owner = THIS_MODULE,
	.open = fwctl_fops_open,
	.release = fwctl_fops_release,
	.unlocked_ioctl = fwctl_fops_ioctl,
};

static void fwctl_device_release(struct device *device)
{
	struct fwctl_device *fwctl =
		container_of(device, struct fwctl_device, dev);

#ifdef HAVE_IDA_ALLOC
	ida_free(&fwctl_ida, fwctl->dev.devt - fwctl_dev);
#else
	ida_simple_remove(&fwctl_ida, fwctl->dev.devt - fwctl_dev);
#endif
	mutex_destroy(&fwctl->uctx_list_lock);
	kfree(fwctl);
}

#ifdef HAVE_DEVNODE_GET_CONST_DEVICE
static char *fwctl_devnode(const struct device *dev, umode_t *mode)
#else
static char *fwctl_devnode(struct device *dev, umode_t *mode)
#endif
{
	return kasprintf(GFP_KERNEL, "fwctl/%s", dev_name(dev));
}

static struct class fwctl_class = {
	.name = "fwctl",
	.dev_release = fwctl_device_release,
	.devnode = fwctl_devnode,
};

static struct fwctl_device *
_alloc_device(struct device *parent, const struct fwctl_ops *ops, size_t size)
{
	struct fwctl_device *fwctl __free(kfree) = kzalloc(size, GFP_KERNEL);
	int devnum;

	if (!fwctl)
		return NULL;
	fwctl->dev.class = &fwctl_class;
	fwctl->dev.parent = parent;
	init_rwsem(&fwctl->registration_lock);
	mutex_init(&fwctl->uctx_list_lock);
	INIT_LIST_HEAD(&fwctl->uctx_list);

#ifdef HAVE_IDA_ALLOC_MAX
	devnum = ida_alloc_max(&fwctl_ida, FWCTL_MAX_DEVICES - 1, GFP_KERNEL);
#else
	devnum = ida_simple_get(&fwctl_ida, 0, FWCTL_MAX_DEVICES, GFP_KERNEL);
#endif
	if (devnum < 0)
		return NULL;
	fwctl->dev.devt = fwctl_dev + devnum;

	device_initialize(&fwctl->dev);
#ifdef HAVE_AUTO_TYPE
	return_ptr(fwctl);
#else
	return fwctl;
#endif
}

/* Drivers use the fwctl_alloc_device() wrapper */
struct fwctl_device *_fwctl_alloc_device(struct device *parent,
					 const struct fwctl_ops *ops,
					 size_t size)
{
	struct fwctl_device *fwctl __free(fwctl) =
		_alloc_device(parent, ops, size);

	if (!fwctl)
		return NULL;

	cdev_init(&fwctl->cdev, &fwctl_fops);
	fwctl->cdev.owner = THIS_MODULE;

	if (dev_set_name(&fwctl->dev, "fwctl%d", fwctl->dev.devt - fwctl_dev))
		return NULL;

	fwctl->ops = ops;
#ifdef HAVE_AUTO_TYPE
	return_ptr(fwctl);
#else
	return fwctl;
#endif
}
EXPORT_SYMBOL_NS_GPL(_fwctl_alloc_device, FWCTL);

/**
 * fwctl_register - Register a new device to the subsystem
 * @fwctl: Previously allocated fwctl_device
 *
 * On return the device is visible through sysfs and /dev, driver ops may be
 * called.
 */
int fwctl_register(struct fwctl_device *fwctl)
{
	int ret;

	ret = cdev_device_add(&fwctl->cdev, &fwctl->dev);
	if (ret)
		return ret;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(fwctl_register, FWCTL);

/**
 * fwctl_unregister - Unregister a device from the subsystem
 * @fwctl: Previously allocated and registered fwctl_device
 *
 * Undoes fwctl_register(). On return no driver ops will be called. The
 * caller must still call fwctl_put() to free the fwctl.
 *
 * Unregister will return even if userspace still has file descriptors open.
 * This will call ops->close_uctx() on any open FDs and after return no driver
 * op will be called. The FDs remain open but all fops will return -ENODEV.
 *
 * The design of fwctl allows this sort of disassociation of the driver from the
 * subsystem primarily by keeping memory allocations owned by the core subsytem.
 * The fwctl_device and fwctl_uctx can both be freed without requiring a driver
 * callback. This allows the module to remain unlocked while FDs are open.
 */
void fwctl_unregister(struct fwctl_device *fwctl)
{
	struct fwctl_uctx *uctx;

	cdev_device_del(&fwctl->cdev, &fwctl->dev);

	/* Disable and free the driver's resources for any still open FDs. */
	guard(rwsem_write)(&fwctl->registration_lock);
	guard(mutex)(&fwctl->uctx_list_lock);
	while ((uctx = list_first_entry_or_null(&fwctl->uctx_list,
						struct fwctl_uctx,
						uctx_list_entry)))
		fwctl_destroy_uctx(uctx);

	/*
	 * The driver module may unload after this returns, the op pointer will
	 * not be valid.
	 */
	fwctl->ops = NULL;
}
EXPORT_SYMBOL_NS_GPL(fwctl_unregister, FWCTL);

static int __init fwctl_init(void)
{
	int ret;

	BUILD_BUG_ON(FWCTL_MAX_DEVICES > (1U << MINORBITS));
	ret = alloc_chrdev_region(&fwctl_dev, 0, FWCTL_MAX_DEVICES, "fwctl");
	if (ret)
		return ret;

	ret = class_register(&fwctl_class);
	if (ret)
		goto err_chrdev;
	return 0;

err_chrdev:
	unregister_chrdev_region(fwctl_dev, FWCTL_MAX_DEVICES);
	return ret;
}

static void __exit fwctl_exit(void)
{
	class_unregister(&fwctl_class);
	unregister_chrdev_region(fwctl_dev, FWCTL_MAX_DEVICES);
}

module_init(fwctl_init);
module_exit(fwctl_exit);
MODULE_DESCRIPTION("fwctl device firmware access framework");
MODULE_LICENSE("GPL");
