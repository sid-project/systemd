/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * probe disks for filesystems and partitions
 *
 * Copyright (C) 2017-2018 Peter Rajnoha <prajnoha@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "device-private.h"
#include "device-util.h"
#include "parse-util.h"
#include "socket-util.h"
#include "udev-builtin.h"

#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

#define SID_BUILTIN_PROTOCOL     1
#define SID_BUILTIN_MAJOR        0
#define SID_BUILTIN_MINOR        0
#define SID_BUILTIN_RELEASE      1

#define SID_BUILTIN_SOCKET_PATH "\0sid-ubridge.socket"

#define SID_CMD_REPLY            1
#define SID_CMD_VERSION          2
#define SID_CMD_SCAN             3
#define SID_CMD_CHECKPOINT       4

#define SID_STATUS_MASK_OVERALL  0x0000000000000001
#define SID_STATUS_SUCCESS       0x0000000000000000
#define SID_STATUS_FAILURE       0x0000000000000001

#define str(v) #v
#define xstr(v) str(v)

int sid_socket_fd = -1;
int sid_connected = 0;

#define SID_MSG_LEN_TYPE uint32_t
#define SID_MSG_LEN_TYPE_SIZE sizeof(SID_MSG_LEN_TYPE)

struct sid_msg_header {
        SID_MSG_LEN_TYPE len;
        uint8_t protocol;
        uint8_t cmd_number;
        uint64_t status;
        char data[0];
} __attribute__((packed));

struct sid_msg_version {
        uint16_t major;
        uint16_t minor;
        uint16_t release;
} __attribute__((packed));

struct raw_buffer {
        char *mem;
        SID_MSG_LEN_TYPE allocated;
        SID_MSG_LEN_TYPE used;
        SID_MSG_LEN_TYPE expected;
};

#define SID_MSG_HEADER_LEN (sizeof(struct sid_msg_header))
#define SID_MSG_MAX_LEN (SID_MSG_LEN_TYPE_SIZE - SID_MSG_HEADER_LEN)
#define SID_MSG_VERSION_LEN (sizeof(struct sid_msg_version))

static int sid_connect(struct sd_device *dev, bool test)
{
        struct sockaddr_un addr = { .sun_family = AF_UNIX,
                                    .sun_path = SID_BUILTIN_SOCKET_PATH,
                                  };

        if (sid_socket_fd < 0) {
                if ((sid_socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0) {
                        log_device_error_errno(dev, errno, "Failed to create SID socket: %m");
                        return -errno;
                }
        }

        if (!sid_connected) {
                if (connect(sid_socket_fd, (struct sockaddr *) &addr, SOCKADDR_UN_LEN(addr))) {
                        close(sid_socket_fd);
                        sid_socket_fd = -1;
                        log_device_error_errno(dev, errno, "Failed to connect to SID daemon: %m");
                        return -errno;
                }
                sid_connected = 1;
                log_device_debug(dev, "SID bridge socket connected");
        }

        return 0;
}

static int sid_send_msg(struct sd_device *dev, struct iovec *iov, int iovcnt)
{
        size_t buf_len;
        ssize_t len;
        int i;

        for (i = 0, buf_len = 0; i < iovcnt; i++)
                buf_len += iov[i].iov_len;

        do
                len = writev(sid_socket_fd, iov, iovcnt);
        while (len < 0 && IN_SET(errno, EAGAIN, EINTR));

        if ((len < 0) || ((size_t) len != buf_len)) {
                log_device_error_errno(dev, errno, "Failed to send message to SID: %m");
                return -1;
        }

        return 0;
}

static int sid_recv_msg(struct sd_device *dev, struct raw_buffer *raw)
{
        ssize_t n;
        void *p;

        if (!(raw->mem = malloc(SID_MSG_LEN_TYPE_SIZE))) {
                errno = ENOMEM;
                goto fail;
        }

        raw->allocated = SID_MSG_LEN_TYPE_SIZE;
        raw->expected = raw->used = 0;

        while (1) {
                n = read(sid_socket_fd, raw->mem + raw->used, raw->allocated - raw->used);
                if (n > 0) {
                        raw->used += n;
                        if (!raw->expected) {
                                if (raw->used >= SID_MSG_LEN_TYPE_SIZE) {
                                        raw->expected = *((SID_MSG_LEN_TYPE *) raw->mem);

                                        if (!(p = realloc(raw->mem, raw->expected))) {
                                                errno = ENOMEM;
                                                goto fail;
                                        }
                                        raw->mem = p;
                                        raw->allocated = raw->expected;
                                }
                        } else if (raw->used == raw->expected)
                                break;
                } else if (n < 0) {
                        if (!IN_SET(errno, EAGAIN, EINTR))
                                goto fail;
                } else {
                        if (!raw->expected || (raw->used != raw->expected)) {
                                errno = EBADE;
                                goto fail;
                        }
                        break;
                }
        }

        return 0;
fail:
        log_device_error_errno(dev, errno, "Failed to receive message from SID: %m");
        if (raw->mem)
                free(raw->mem);

        raw->mem = NULL;
        raw->allocated = raw->used = raw->expected = 0;
        return -1;
}

/* Code copied from udev_device_get_seqnum function as this is not exposed by sd-device.h API yet. */
static unsigned long long sid_device_get_seqnum(struct sd_device *dev)
{
        const char *seqnum;
        unsigned long long ret;
        int r;

        r = sd_device_get_property_value(dev, "SEQNUM", &seqnum);
        if (r == -ENOENT)
                return 0;
        else if (r < 0) {
                errno = -r;
                return 0;
        }

        r = safe_atollu(seqnum, &ret);
        if (r < 0) {
                errno = -r;
                return 0;
        }

        return ret;
}

static int sid_do_cmd_version(struct sd_device *dev, bool test, struct raw_buffer *raw_response)
{
        struct sid_msg_header msg_header;
        struct sid_msg_version msg_version;
        struct iovec iov[2];

        (void) sid_connect(dev, test);

        if (!sid_connected)
                return 0;

        msg_header.len = SID_MSG_HEADER_LEN + SID_MSG_VERSION_LEN;
        msg_header.protocol = SID_BUILTIN_PROTOCOL;
        msg_header.cmd_number = SID_CMD_VERSION;
        msg_header.status = (uint64_t) sid_device_get_seqnum(dev);
        iov[0].iov_base = &msg_header;
        iov[0].iov_len = SID_MSG_HEADER_LEN;

        msg_version.major = SID_BUILTIN_MAJOR;
        msg_version.minor = SID_BUILTIN_MINOR;
        msg_version.release = SID_BUILTIN_RELEASE;
        iov[1].iov_base = &msg_version;
        iov[1].iov_len = SID_MSG_VERSION_LEN;

        if (sid_send_msg(dev, iov, 2) < 0 || sid_recv_msg(dev, raw_response) < 0)
                return -1;

        return 0;
}

static int sid_cmd_version(struct sd_device *dev, int argc, char *argv[], bool test)
{
        struct raw_buffer raw_response;
        struct sid_msg_header *response_msg_header;
        struct sid_msg_version *response_msg_version;
        const char *sid_bridge_status;
        char str[8];

        if (sid_do_cmd_version(dev, test, &raw_response) < 0)
                return EXIT_FAILURE;

        if (sid_connected) {
                response_msg_header = (struct sid_msg_header *) raw_response.mem;
                response_msg_version = (struct sid_msg_version *) response_msg_header->data;

                snprintf(str, sizeof(str), "%"PRIu16, response_msg_header->protocol);
                udev_builtin_add_property(dev, test, "SID_PROTOCOL", str);

                snprintf(str, sizeof(str), "%"PRIu16, response_msg_version->major);
                udev_builtin_add_property(dev, test, "SID_MAJOR", str);

                snprintf(str, sizeof(str), "%"PRIu16, response_msg_version->minor);
                udev_builtin_add_property(dev, test, "SID_MINOR", str);

                snprintf(str, sizeof(str), "%"PRIu16, response_msg_version->release);
                udev_builtin_add_property(dev, test, "SID_RELEASE", str);
        }

        udev_builtin_add_property(dev, test, "SID_BUILTIN_PROTOCOL", xstr(SID_BUILTIN_PROTOCOL));
        udev_builtin_add_property(dev, test, "SID_BUILTIN_MAJOR", xstr(SID_BUILTIN_MAJOR));
        udev_builtin_add_property(dev, test, "SID_BUILTIN_MINOR", xstr(SID_BUILTIN_MINOR));
        udev_builtin_add_property(dev, test, "SID_BUILTIN_RELEASE", xstr(SID_BUILTIN_RELEASE));

        return EXIT_SUCCESS;
}

static int sid_cmd_active(struct sd_device *dev, int argc, char *argv[], bool test)
{
        struct raw_buffer raw_response;
        struct sid_msg_header *response_msg_header;
        struct sid_msg_version *response_msg_version;
        const char *status;

        if (sid_do_cmd_version(dev, test, &raw_response) < 0)
                return EXIT_FAILURE;

        if (sid_connected) {
                response_msg_header = (struct sid_msg_header *) raw_response.mem;

                if (response_msg_header->protocol != SID_BUILTIN_PROTOCOL)
                        status = "incompatible";
                else
                        status = "active";
        } else
                status = "inactive";

        udev_builtin_add_property(dev, test, "SID_BRIDGE_STATUS", status);

        return EXIT_SUCCESS;
}

static int sid_add_key_value_pair(struct sd_device *dev, bool test, char *key)
{
        char *value;
        size_t key_len;
        int r;

        if (!(value = strchr(key, '=')) || !*(value++))
                return EXIT_FAILURE;

        key_len = value - key - 1;
        key[key_len] = '\0';

        r = udev_builtin_add_property(dev, test, key, value);

        key[key_len] = '=';

        return r;
}

static int sid_add_udev_env(struct sd_device *dev, bool test, char *buf, size_t buf_len)
{
        size_t i = 0;
        char *str, *delim;

        while (i < buf_len) {
                str = buf + i;

                if (!(delim = memchr(str, '\0', buf_len - i)))
                        return EXIT_FAILURE;

                if (sid_add_key_value_pair(dev, test, str))
                        return EXIT_FAILURE;

                i += delim - str + 1;
        }

        return EXIT_SUCCESS;
}

static int sid_cmd_scan(struct sd_device *dev, int argc, char *argv[], bool test)
{
        struct sid_msg_header msg_header;
        struct sid_msg_header *response_header;
        dev_t devnum;
        const char *buf;
        size_t buf_len;
        struct iovec iov[3];
        struct raw_buffer raw_response;

        if (sid_connect(dev, test) < 0)
                return EXIT_FAILURE;

        if (sd_device_get_devnum(dev, &devnum) < 0)
                return EXIT_FAILURE;

        if (device_get_properties_nulstr(dev, (const uint8_t **) &buf, &buf_len) < 0 || buf_len > SID_MSG_MAX_LEN)
                return EXIT_FAILURE;

        msg_header.len = SID_MSG_HEADER_LEN + sizeof(dev_t) + buf_len;
        msg_header.protocol = SID_BUILTIN_PROTOCOL;
        msg_header.cmd_number = SID_CMD_SCAN;
        msg_header.status = (uint64_t) sid_device_get_seqnum(dev);

        iov[0].iov_base = &msg_header;
        iov[0].iov_len = SID_MSG_HEADER_LEN;

        iov[1].iov_base = &devnum;
        iov[1].iov_len = sizeof(devnum);

        iov[2].iov_base = (void *) buf;
        iov[2].iov_len = buf_len;

        if (sid_send_msg(dev, iov, 3) < 0 || sid_recv_msg(dev, &raw_response) < 0)
               return EXIT_FAILURE;

        response_header = (struct sid_msg_header *) raw_response.mem;
        sid_add_udev_env(dev, test, response_header->data, response_header->len - (response_header->data - (char *) response_header));

        return EXIT_SUCCESS;
}

static int sid_cmd_checkpoint(struct sd_device *dev, int argc, char *argv[], bool test)
{
        struct sid_msg_header msg_header;
        char *buf = NULL;
        ssize_t buf_len = 0;
        struct iovec iov[2];
        struct raw_buffer raw_response;

        if (sid_connect(dev, test) < 0)
                return EXIT_FAILURE;

        msg_header.len = SID_MSG_HEADER_LEN + buf_len;
        msg_header.cmd_number = SID_CMD_CHECKPOINT;
        msg_header.status = (uint64_t) sid_device_get_seqnum(dev);
        iov[0].iov_base = &msg_header;
        iov[0].iov_len = SID_MSG_HEADER_LEN;

        iov[1].iov_base = buf;
        iov[1].iov_len = buf_len;

        if (sid_send_msg(dev, iov, 2) < 0 || sid_recv_msg(dev, &raw_response) < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}

static int builtin_sid(struct sd_device *dev, int argc, char *argv[], bool test)
{
        const char *cmd;

        if (argc < 2) {
                log_device_error(dev, "Undefined command.");
                return EXIT_FAILURE;
        }

        cmd = argv[1];
        argc = argc - 2;
        argv = argv + 2;

        if (!strcmp(cmd, "scan"))
                return sid_cmd_scan(dev, argc, argv, test);
        else if (!strcmp(cmd, "checkpoint"))
                return sid_cmd_checkpoint(dev, argc, argv, test);
        else if (!strcmp(cmd, "active"))
                return sid_cmd_active(dev, argc, argv, test);
        else if (!strcmp(cmd, "version"))
                return sid_cmd_version(dev, argc, argv, test);
        else {
                log_device_error(dev, "Unknown command.");
                return EXIT_FAILURE;
        }
}

static int builtin_sid_init(void)
{
        log_debug("Storage Instantiation Daemon link init.");

        return 0;
}

static void builtin_sid_exit(void)
{
        if (sid_socket_fd >= 0) {
                log_debug("SID bridge socket closed");
                close(sid_socket_fd);
                sid_connected = 0;
                sid_socket_fd = -1;
        }

        log_debug("Storage Instantiation Daemon link exit.");
}

const UdevBuiltin udev_builtin_sid = {
        .name = "sid",
        .cmd = builtin_sid,
        .init = builtin_sid_init,
        .exit = builtin_sid_exit,
        .help = "Storage Instantiation Daemon link",
};
