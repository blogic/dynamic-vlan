/* SPDX-License-Identifier: BSD-3-Clause */

#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/ulog.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubus.h>
#include <uci.h>
#include <uci_blob.h>

static struct publisher {
	char *path;
	int wildcard;
} publisher[] = {
	{
		.path = "hostapd.wlan",
		.wildcard = 1,
	},
};

struct subscriber {
	struct avl_node avl;
	uint32_t id;
	struct publisher *publisher;
	struct ubus_subscriber subscriber;
};

static struct avl_tree subscribers;
static struct ubus_auto_conn conn;
static struct blob_buf b;
static uint32_t netifd;
static char *wan;

static int
avl_intcmp(const void *k1, const void *k2, void *ptr)
{
	return *((uint32_t *)k1) != *((uint32_t *)k2);
}

static struct publisher*
publisher_match(const char *path)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(publisher); i++) {
		int len = strlen(publisher[i].path);

		if (publisher[i].wildcard && strncmp(path, publisher[i].path, len))
			continue;
		if (!publisher[i].wildcard && strcmp(path, publisher[i].path))
			continue;
		return &publisher[i];
	}
	return NULL;
}

static int
subscriber_notify_cb(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	enum {
		VLAN_IFNAME,
		VLAN_ID,
		__VLAN_MAX
	};

	static const struct blobmsg_policy vlan_policy[__VLAN_MAX] = {
		[VLAN_ID] = { .name = "vlan_id", .type = BLOBMSG_TYPE_INT32 },
		[VLAN_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__VLAN_MAX];

	struct ubus_subscriber *subscriber = container_of(obj, struct ubus_subscriber, obj);
	struct subscriber *sub = container_of(subscriber, struct subscriber, subscriber);
	uint32_t vlan_id;
	char *ifname, vlan[16];
	void *c;

	if (!sub)
		return 0;

	if (strcmp(method, "vlan_add"))
		return 0;

	blobmsg_parse(vlan_policy, __VLAN_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[VLAN_ID] || !tb[VLAN_IFNAME]) {
		ULOG_ERR("received a bad vlan event\n");
		return 0;
	}

	vlan_id = blobmsg_get_u32(tb[VLAN_ID]);
	ifname = blobmsg_get_string(tb[VLAN_IFNAME]);

	ULOG_INFO("received a dynamic vlan event ifname=%s vlan_id=%d telling neiftd about it\n", ifname, vlan_id);

	if (!netifd) {
		ULOG_ERR("failed to inform netifd as its ubus id is unknown\n");
		return 0;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", wan);
	c = blobmsg_open_array(&b, "vlan");
	snprintf(vlan, sizeof(vlan), "%d:t", vlan_id);
	blobmsg_add_string(&b, NULL, vlan);
	blobmsg_close_array(&b, c);

	if (ubus_invoke(&conn.ctx, netifd, "add_device", b.head, NULL, 0, 1000))
		ULOG_ERR("failed to add wan port\n");

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", ifname);
	blobmsg_add_u8(&b, "link-ext", true);
	c = blobmsg_open_array(&b, "vlan");
	snprintf(vlan, sizeof(vlan), "%d", vlan_id);
	blobmsg_add_string(&b, NULL, vlan);
	blobmsg_close_array(&b, c);

	if (ubus_invoke(&conn.ctx, netifd, "add_device", b.head, NULL, 0, 1000))
		ULOG_ERR("failed to add device\n");

	return 0;
}

static void
subscriber_del(uint32_t id)
{
	struct subscriber *p = avl_find_element(&subscribers, &id, p, avl);

	if (p)
		avl_delete(&subscribers, &p->avl);
}

static void
subscriber_add(struct ubus_context *ctx, char *path, uint32_t id)
{
	struct publisher *publisher = publisher_match(path);
	struct subscriber *sub;

	if (!publisher)
		return;
	sub = malloc(sizeof(*sub));

	memset(sub, 0, sizeof(*sub));
	sub->id = id;
	sub->publisher = publisher;
	sub->avl.key = &sub->id;
	sub->subscriber.cb = subscriber_notify_cb;
	if (ubus_register_subscriber(ctx, &sub->subscriber) ||
	    ubus_subscribe(ctx, &sub->subscriber, id)) {
		ULOG_ERR("failed to register ubus publisher\n");
		free(sub);
	} else {
		avl_insert(&subscribers, &sub->avl);
		ULOG_NOTE("Subscribe to %s (%u)\n", path, id);
	}
}

static void
handle_status(struct ubus_context *ctx,  struct ubus_event_handler *ev,
	     const char *type, struct blob_attr *msg)
{
	enum {
		EVENT_ID,
		EVENT_PATH,
		__EVENT_MAX
	};

	static const struct blobmsg_policy status_policy[__EVENT_MAX] = {
		[EVENT_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
		[EVENT_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__EVENT_MAX];
	char *path;
	uint32_t id;

	blobmsg_parse(status_policy, __EVENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[EVENT_ID] || !tb[EVENT_PATH])
		return;

	path = blobmsg_get_string(tb[EVENT_PATH]);
	id = blobmsg_get_u32(tb[EVENT_ID]);

	if (!strcmp(path, "network.interface.up_none")) {
		if (!strcmp("ubus.object.remove", type))
			netifd = 0;
		else
			netifd = id;
		return;
	}

	if (!strcmp("ubus.object.remove", type)) {
		subscriber_del(id);
		return;
	}

	subscriber_add(ctx, path, id);
}

static struct ubus_event_handler status_handler = { .cb = handle_status };

static void
receive_list_result(struct ubus_context *ctx, struct ubus_object_data *obj,
		    void *priv)
{
	char *path = strdup(obj->path);

	subscriber_add(ctx, path, obj->id);
	free(path);
}

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ULOG_NOTE("connected to ubus\n");

	ubus_register_event_handler(ctx, &status_handler, "ubus.object.add");
	ubus_register_event_handler(ctx, &status_handler, "ubus.object.remove");

	ubus_lookup_id(ctx, "network.interface.up_none", &netifd);
	ubus_lookup(ctx, NULL, receive_list_result, NULL);
}

int
main(int argc, char **argv)
{
	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "dynamic-vlan");
	if (argc != 2) {
		ULOG_ERR("missing wan port info\n");
		return -1;
	}
	wan = argv[1];
	avl_init(&subscribers, avl_intcmp, false, NULL);
	uloop_init();
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
	uloop_run();
	uloop_done();
	ubus_auto_shutdown(&conn);

	return 0;
}
