#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/list.h>
#include "message_slot.h"

#define DEVICE_NAME ("message_slot")

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Avner Spira");
MODULE_DESCRIPTION("message slot device driver");

typedef struct channel {
    uint id;
    int len;
    char msg[128];
} channel_t;

typedef struct channel_node_s {
    struct  channel channel;
    struct channel_node_s * next;
} channel_node_t;

typedef struct minor_node_s {
    uint32_t minor;
    channel_node_t * channel_list;
    struct minor_node_s * next;
} minor_node_t;

typedef struct file_private_data_s {
    minor_node_t * minor_node;
    channel_t * current_channel;
} file_data_t;

static minor_node_t * minor_list = NULL;

static int device_open(struct inode * ip, struct file * file);
static int device_release(struct inode * ip, struct file * file);
static long device_ioctl(struct file * file, uint ioctl_num, ulong ioctl_param);
static ssize_t device_read(struct file * file, char * buffer, size_t size, loff_t * offset);
static ssize_t device_write(struct file * file, const char * buffer, size_t size, loff_t * offset);

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_release,
    .read = device_read,
    .write = device_write,
    .unlocked_ioctl = device_ioctl
};

static int __init message_slot_init(void) {
    int ret = 0;
    if ((ret = register_chrdev(MAJOR_NUM, DEVICE_NAME, &fops)) == -1) {
        printk(KERN_ERR "message slot device registration failed, error: %d\n", ret);
        return -1;
    }
    
    printk(KERN_DEFAULT "message slot device registration succsess\n");
    return 0;
}

static void __exit message_slot_exit(void) {
    unregister_chrdev(MAJOR_NUM, DEVICE_NAME);

    minor_node_t * minor_node = minor_list;
    minor_node_t * next_minor_node = NULL;

    while (minor_node != NULL) {
        next_minor_node = minor_node->next;

        channel_node_t * channel_node = minor_node->channel_list;
        channel_node_t * next_channel_node = NULL;
        while (channel_node != NULL) {
            next_channel_node = channel_node->next;
            kfree(channel_node);
            channel_node = next_channel_node;
        }

        kfree(minor_node);
        minor_node = next_minor_node;
    }

    minor_list = NULL;
}

module_init(message_slot_init);
module_exit(message_slot_exit);

static minor_node_t* get_minor_node(uint minor) {
    minor_node_t * node = minor_list;
    while (node != NULL) {
        if (node->minor == minor) {
            return node;
        }
        node = node->next;
    }
    /* emplace minor node */
    node = kmalloc(sizeof(minor_node_t), GFP_KERNEL);
    if (node == NULL) {
        return NULL;
    }

    node->minor = minor;
    node->channel_list = NULL;
    /* pushes node */
    node->next = minor_list;
    minor_list = node;
    return node;
}

static channel_node_t* get_channel_node(minor_node_t * minor_node, uint32_t id) {
    channel_node_t * node = minor_node->channel_list;
    while (node != NULL) {
        if (node->channel.id == id) {
            return node;
        }
        node = node->next;
    }
    /* Allocate channel node */
    node = kmalloc(sizeof(channel_node_t), GFP_KERNEL);
    if (node == NULL) {
        return NULL;
    }
    node->channel = (channel_t){.id = id, .msg = {0}, .len = 0};
    node->next = minor_node->channel_list;
    minor_node->channel_list = node;
    return node;
}

static int device_open(struct inode * inode, struct file * file) {
    uint minor = iminor(inode);
    minor_node_t* minor_node = get_minor_node(minor);
    if (minor_node == NULL) {
        return -ENOMEM;
    }
    file_data_t * file_data = kmalloc(sizeof(file_data_t), GFP_KERNEL);
    if (file_data == NULL) {
        return -ENOMEM;
    }
    file_data->current_channel = NULL;
    file_data->minor_node = minor_node;

    file->private_data = file_data;
    file->f_mode |= FMODE_READ | FMODE_WRITE;
    return 0;
}

static int device_release(struct inode * ip, struct file * file) {
    if (file->private_data == NULL) {
        panic("file->private_data = NULL\n");
        return -EINVAL;
    }
    kfree(file->private_data);
    return 0;
}

static long device_ioctl(struct file * file, uint ioctl_cmd, ulong ioctl_param) {
    switch (ioctl_cmd)
    {
    case MSG_SLOT_CHANNEL:
        file_data_t * file_data = (file_data_t *)file->private_data;
        channel_node_t * minor_node = get_channel_node(file_data->minor_node, ioctl_param);
        if (minor_node == NULL) {
            return -ENOMEM;
        }
        file_data->current_channel = &minor_node->channel;
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

static ssize_t device_read(struct file * file, char * buffer, size_t size, loff_t * offset)
{
    ulong ret = 0;
    file_data_t * file_data = (file_data_t *)file->private_data;
    channel_t * channel = file_data->current_channel;
    if (channel == NULL) {
        return -EINVAL;
    }
    if (channel->len == 0) {
        return -EWOULDBLOCK;
    }
    if (channel->len > size) {
        return -ENOSPC;
    }
    if ((ret = copy_to_user(buffer, channel->msg, channel->len)) != 0) {
        return -EFAULT;
    }
    return channel->len;
}

static ssize_t device_write(struct file * file, const char * buffer, size_t size, loff_t * offset) {
    ulong ret = 0;
    file_data_t * file_data = (file_data_t *)file->private_data;
    channel_t * channel = file_data->current_channel;
    if (channel == NULL) {
        return -EINVAL;
    }
    if (size <= 0 || size > MAX_MSG_SIZE) {
        return -EMSGSIZE;
    }
    if ((ret = copy_from_user(channel->msg, buffer, size)) != 0) {
        if (ret > 0) {
            channel->len = size - ret;
        }
        return -EFAULT;
    }

    channel->len = size;
    return channel->len;
}
