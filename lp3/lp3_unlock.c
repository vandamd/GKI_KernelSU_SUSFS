// SPDX-License-Identifier: GPL-2.0-only
/* Fixed-purpose unlock-record staging for TLP301 / 00WW_1_440000. */
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>
#include <crypto/sha.h>
#include <asm/unaligned.h>

#define RECORD_SIZE 4096
#define RECORD_OFFSET 12288
#define MFD_SIZE 131072
#define ABL_SIZE 1048576
#define REQUEST_SIZE (8 + SHA256_DIGEST_SIZE + RECORD_SIZE)

static DEFINE_MUTEX(unlock_mutex);
static bool write_attempted;

static bool authorised(void)
{
	return uid_eq(current_euid(), GLOBAL_ROOT_UID) &&
		ns_capable(&init_user_ns, CAP_SYS_RAWIO);
}

/* Resolve a kernel partition label, never a caller-supplied path or symlink. */
static struct block_device *open_partition(const char *label, fmode_t mode,
					   loff_t size)
{
	struct block_device *bdev;
	dev_t dev = name_to_dev_t(label);

	if (!dev)
		return ERR_PTR(-ENODEV);
	bdev = blkdev_get_by_dev(dev, mode, &unlock_mutex);
	if (IS_ERR(bdev))
		return bdev;
	if (!bdev->bd_part || !bdev->bd_part->partno ||
	    (size && i_size_read(bdev->bd_inode) != size) ||
	    bdev_logical_block_size(bdev) > RECORD_SIZE) {
		blkdev_put(bdev, mode);
		return ERR_PTR(-ENODEV);
	}
	return bdev;
}

static int block_io(struct block_device *bdev, loff_t offset, u8 *buffer,
		    bool write)
{
	struct page *page;
	struct bio *bio;
	int ret;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	bio = bio_alloc(GFP_KERNEL, 1);
	if (!bio) {
		__free_page(page);
		return -ENOMEM;
	}
	if (write)
		memcpy(page_address(page), buffer, RECORD_SIZE);
	bio_set_dev(bio, bdev);
	bio->bi_iter.bi_sector = offset >> 9;
	bio->bi_opf = write ? REQ_OP_WRITE | REQ_SYNC | REQ_FUA : REQ_OP_READ;
	if (bio_add_page(bio, page, RECORD_SIZE, 0) != RECORD_SIZE) {
		ret = -EIO;
		goto out;
	}
	ret = submit_bio_wait(bio);
	if (!ret && !write)
		memcpy(buffer, page_address(page), RECORD_SIZE);
out:
	bio_put(bio);
	__free_page(page);
	return ret;
}

static int read_mfd(struct block_device *bdev, u8 *buffer)
{
	loff_t offset;
	int ret;

	for (offset = 0; offset < MFD_SIZE; offset += RECORD_SIZE) {
		ret = block_io(bdev, offset, buffer + offset, false);
		if (ret)
			return ret;
	}
	return 0;
}

static int check_bootloader(const char *label, const char *expected)
{
	struct block_device *bdev;
	struct sha256_state hash;
	u8 digest[SHA256_DIGEST_SIZE], wanted[SHA256_DIGEST_SIZE];
	u8 *buffer;
	loff_t offset;
	int ret;

	ret = hex2bin(wanted, expected, sizeof(wanted));
	if (ret)
		return ret;
	bdev = open_partition(label, FMODE_READ, ABL_SIZE);
	if (IS_ERR(bdev))
		return PTR_ERR(bdev);
	buffer = kmalloc(RECORD_SIZE, GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto out;
	}
	sha256_init(&hash);
	for (offset = 0; offset < ABL_SIZE; offset += RECORD_SIZE) {
		ret = block_io(bdev, offset, buffer, false);
		if (ret)
			goto free_buffer;
		sha256_update(&hash, buffer, RECORD_SIZE);
	}
	sha256_final(&hash, digest);
	ret = memcmp(digest, wanted, sizeof(wanted)) ? -EKEYREJECTED : 0;
free_buffer:
	kfree(buffer);
out:
	blkdev_put(bdev, FMODE_READ);
	return ret;
}

/* OTA updates can place this exact pair in either slot order. */
static int check_bootloaders(void)
{
	const char *current = "f51fa45314960b3da6f4dfc68e4d2bbc6b821f6a3f6221f77352f4e50e7af98a";
	const char *previous = "2a983666338dd04e6b2f8c4135c1cc8ae5a65457f9e557398d04774e7a282b30";
	int ret;

	ret = check_bootloader("PARTLABEL=abl_a", current);
	if (ret == -EKEYREJECTED) {
		ret = check_bootloader("PARTLABEL=abl_a", previous);
		if (ret)
			return ret;
		return check_bootloader("PARTLABEL=abl_b", current);
	}
	if (ret)
		return ret;
	return check_bootloader("PARTLABEL=abl_b", previous);
}

static int check_oem_unlock(void)
{
	struct block_device *bdev;
	loff_t size;
	u8 *buffer;
	int ret;

	bdev = open_partition("PARTLABEL=frp", FMODE_READ, 0);
	if (IS_ERR(bdev))
		return PTR_ERR(bdev);
	size = i_size_read(bdev->bd_inode);
	if (size < RECORD_SIZE || size > 1048576 || size % RECORD_SIZE) {
		ret = -ENODEV;
		goto out;
	}
	buffer = kmalloc(RECORD_SIZE, GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto out;
	}
	ret = block_io(bdev, size - RECORD_SIZE, buffer, false);
	if (!ret && buffer[RECORD_SIZE - 1] != 1)
		ret = -EPERM;
	kfree(buffer);
out:
	blkdev_put(bdev, FMODE_READ);
	return ret;
}

static bool valid_record(const u8 *record)
{
	u32 length = get_unaligned_le32(record + 0x910);
	u32 der_length;

	if (get_unaligned_le32(record) != 0x43655274 ||
	    get_unaligned_le32(record + 4) != 1 ||
	    get_unaligned_le32(record + 8) != 1 ||
	    get_unaligned_le32(record + 0x10c) != 256 ||
	    get_unaligned_le32(record + 0x914) != 0x54724563 ||
	    length < 4 || length > 0x800)
		return false;
	/* The browser verifies the signature; firmware consumes the certificate. */
	if (record[0x110] != 0x30 || record[0x111] != 0x82)
		return false;
	der_length = ((u32)record[0x112] << 8) | record[0x113];
	return der_length + 4 == length &&
		!memchr_inv(record + 0x110 + length, 0, 0x800 - length) &&
		!memchr_inv(record + 0x918, 0, RECORD_SIZE - 0x918);
}

static bool empty_record(const u8 *record)
{
	return get_unaligned_le32(record) == 0x43655274 &&
		get_unaligned_le32(record + 0x914) == 0x54724563 &&
		!memchr_inv(record + 4, 0, 0x910) &&
		!memchr_inv(record + 0x918, 0, RECORD_SIZE - 0x918);
}

static int stage_record(const u8 *request)
{
	const fmode_t mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;
	struct block_device *mfd;
	u8 digest[SHA256_DIGEST_SIZE];
	u8 *before, *after;
	int ret;

	ret = check_bootloaders();
	if (ret)
		return ret;
	ret = check_oem_unlock();
	if (ret)
		return ret;
	mfd = open_partition("PARTLABEL=mfd", mode, MFD_SIZE);
	if (IS_ERR(mfd))
		return PTR_ERR(mfd);
	before = kvzalloc(MFD_SIZE, GFP_KERNEL);
	after = kvzalloc(MFD_SIZE, GFP_KERNEL);
	if (!before || !after) {
		ret = -ENOMEM;
		goto out;
	}
	ret = sync_blockdev(mfd);
	if (ret)
		goto out;
	ret = read_mfd(mfd, before);
	if (ret)
		goto out;
	sha256(before, MFD_SIZE, digest);
	if (memcmp(digest, request + 8, sizeof(digest)) ||
	    !empty_record(before + RECORD_OFFSET)) {
		ret = -ESTALE;
		goto out;
	}
	memcpy(before + RECORD_OFFSET, request + 8 + SHA256_DIGEST_SIZE, RECORD_SIZE);
	/* No retry after any write attempt, including a failed or partial write. */
	write_attempted = true;
	ret = block_io(mfd, RECORD_OFFSET, before + RECORD_OFFSET, true);
	if (ret)
		goto invalidate;
	ret = blkdev_issue_flush(mfd, GFP_KERNEL);
	if (ret)
		goto invalidate;
	ret = read_mfd(mfd, after);
	if (!ret && memcmp(before, after, MFD_SIZE))
		ret = -EIO;
invalidate:
	invalidate_bdev(mfd);
out:
	kvfree(before);
	kvfree(after);
	blkdev_put(mfd, mode);
	return ret;
}

static ssize_t lp3_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *position)
{
	u8 *request;
	int ret;

	if (!authorised())
		return -EPERM;
	if (*position || count != REQUEST_SIZE)
		return -EINVAL;
	request = memdup_user(buffer, count);
	if (IS_ERR(request))
		return PTR_ERR(request);
	if (memcmp(request, "LP3ULK1\n", 8) ||
	    !valid_record(request + 8 + SHA256_DIGEST_SIZE)) {
		ret = -EINVAL;
		goto out;
	}
	mutex_lock(&unlock_mutex);
	ret = write_attempted ? -EALREADY : stage_record(request);
	mutex_unlock(&unlock_mutex);
	if (!ret)
		*position += count;
out:
	kfree_sensitive(request);
	return ret ? ret : count;
}

static ssize_t lp3_read(struct file *file, char __user *buffer,
			size_t count, loff_t *position)
{
	static const char version[] = "lp3-unlock-v2\n";

	if (!authorised())
		return -EPERM;
	return simple_read_from_buffer(buffer, count, position, version, sizeof(version) - 1);
}

static const struct file_operations lp3_fops = {
	.owner = THIS_MODULE,
	.open = nonseekable_open,
	.read = lp3_read,
	.write = lp3_write,
	.llseek = no_llseek,
};

static struct miscdevice lp3_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "lp3_unlock",
	.fops = &lp3_fops,
	.mode = 0600,
};

static int __init lp3_unlock_init(void)
{
	BUILD_BUG_ON(PAGE_SIZE != RECORD_SIZE);
	return misc_register(&lp3_device);
}
device_initcall(lp3_unlock_init);
MODULE_LICENSE("GPL");
