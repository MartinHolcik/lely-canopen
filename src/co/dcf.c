/**@file
 * This file is part of the CANopen library; it contains the implementation of
 * the Electronic Data Sheet (EDS) and Device Configuration File (DCF)
 * functions.
 *
 * @see lely/co/dcf.h
 *
 * @copyright 2019 Lely Industries N.V.
 *
 * @author J. S. Seldenthuis <jseldenthuis@lely.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "co.h"

#ifndef LELY_NO_CO_DCF

#include "obj.h"
#include <lely/co/dcf.h>
#include <lely/co/pdo.h>
#include <lely/libc/stdio.h>
#include <lely/libc/strings.h>
#include <lely/util/config.h>
#include <lely/util/diag.h>
#include <lely/util/lex.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static struct __co_dev *__co_dev_init_from_dcf_cfg(
		struct __co_dev *dev, const config_t *cfg);

static int co_dev_parse_cfg(co_dev_t *dev, const config_t *cfg);

static int co_obj_parse_cfg(
		co_obj_t *obj, const config_t *cfg, const char *section);
#ifndef LELY_NO_CO_OBJ_NAME
static int co_obj_parse_names(co_obj_t *obj, const config_t *cfg);
#endif
static int co_obj_parse_values(co_obj_t *obj, const config_t *cfg);
static co_obj_t *co_obj_build(co_dev_t *dev, co_unsigned16_t idx);

static int co_sub_parse_cfg(
		co_sub_t *sub, const config_t *cfg, const char *section);
static co_sub_t *co_sub_build(co_obj_t *obj, co_unsigned8_t subidx,
		co_unsigned16_t type, const char *name);

static int co_rpdo_build(co_dev_t *dev, co_unsigned16_t num, int mask);
static int co_tpdo_build(co_dev_t *dev, co_unsigned16_t num, int mask);

static void co_val_set_id(co_unsigned16_t type, void *val, co_unsigned8_t id);

static co_unsigned16_t config_get_idx(const config_t *cfg, const char *section,
		co_unsigned16_t maxidx, co_unsigned16_t *idx);

struct __co_dev *
__co_dev_init_from_dcf_file(struct __co_dev *dev, const char *filename)
{
	config_t *cfg = config_create(CONFIG_CASE);
	if (!cfg) {
		diag(DIAG_ERROR, get_errc(),
				"unable to create configuration struct");
		goto error_create_cfg;
	}

	if (!config_parse_ini_file(cfg, filename))
		goto error_parse_ini_file;

	if (!__co_dev_init_from_dcf_cfg(dev, cfg))
		goto error_init_dev;

	config_destroy(cfg);

	return dev;

error_init_dev:
error_parse_ini_file:
	config_destroy(cfg);
error_create_cfg:
	return NULL;
}

co_dev_t *
co_dev_create_from_dcf_file(const char *filename)
{
	int errc = 0;

	co_dev_t *dev = __co_dev_alloc();
	if (!dev) {
		errc = get_errc();
		goto error_alloc_dev;
	}

	if (!__co_dev_init_from_dcf_file(dev, filename)) {
		errc = get_errc();
		goto error_init_dev;
	}

	return dev;

error_init_dev:
	__co_dev_free(dev);
error_alloc_dev:
	set_errc(errc);
	return NULL;
}

struct __co_dev *
__co_dev_init_from_dcf_text(struct __co_dev *dev, const char *begin,
		const char *end, struct floc *at)
{
	config_t *cfg = config_create(CONFIG_CASE);
	if (!cfg) {
		diag(DIAG_ERROR, get_errc(),
				"unable to create configuration struct");
		goto error_create_cfg;
	}

	if (!config_parse_ini_text(cfg, begin, end, at))
		goto error_parse_ini_text;

	if (!__co_dev_init_from_dcf_cfg(dev, cfg))
		goto error_init_dev;

	config_destroy(cfg);

	return dev;

error_init_dev:
error_parse_ini_text:
	config_destroy(cfg);
error_create_cfg:
	return NULL;
}

co_dev_t *
co_dev_create_from_dcf_text(const char *begin, const char *end, struct floc *at)
{
	int errc = 0;

	co_dev_t *dev = __co_dev_alloc();
	if (!dev) {
		errc = get_errc();
		goto error_alloc_dev;
	}

	if (!__co_dev_init_from_dcf_text(dev, begin, end, at)) {
		errc = get_errc();
		goto error_init_dev;
	}

	return dev;

error_init_dev:
	__co_dev_free(dev);
error_alloc_dev:
	set_errc(errc);
	return NULL;
}

static struct __co_dev *
__co_dev_init_from_dcf_cfg(struct __co_dev *dev, const config_t *cfg)
{
	assert(dev);
	assert(cfg);

	if (!__co_dev_init(dev, 0xff)) {
		diag(DIAG_ERROR, get_errc(),
				"unable to initialize device description");
		goto error_init_dev;
	}

	if (co_dev_parse_cfg(dev, cfg) == -1)
		goto error_parse_cfg;

	return dev;

error_parse_cfg:
	__co_dev_fini(dev);
error_init_dev:
	return NULL;
}

static int
co_dev_parse_cfg(co_dev_t *dev, const config_t *cfg)
{
	assert(dev);
	assert(cfg);

	const char *val;

	// clang-format off
	if (co_dev_set_vendor_name(dev,
			config_get(cfg, "DeviceInfo", "VendorName")) == -1) {
		// clang-format on
		diag(DIAG_ERROR, get_errc(), "unable to set vendor name");
		goto error_parse_dev;
	}

	val = config_get(cfg, "DeviceInfo", "VendorNumber");
	if (val && *val)
		co_dev_set_vendor_id(dev, strtoul(val, NULL, 0));

	// clang-format off
	if (co_dev_set_product_name(dev,
			config_get(cfg, "DeviceInfo", "ProductName")) == -1) {
		// clang-format on
		diag(DIAG_ERROR, get_errc(), "unable to set product name");
		goto error_parse_dev;
	}

	val = config_get(cfg, "DeviceInfo", "ProductNumber");
	if (val && *val)
		co_dev_set_product_code(dev, strtoul(val, NULL, 0));

	val = config_get(cfg, "DeviceInfo", "RevisionNumber");
	if (val && *val)
		co_dev_set_revision(dev, strtoul(val, NULL, 0));

	// clang-format off
	if (co_dev_set_order_code(dev,
			config_get(cfg, "DeviceInfo", "OrderCode")) == -1) {
		diag(DIAG_ERROR, get_errc(), "unable to set order code");
		goto error_parse_dev;
		// clang-format on
	}

	unsigned int baud = 0;
	val = config_get(cfg, "DeviceInfo", "BaudRate_10");
	if (val && *val && strtoul(val, NULL, 0))
		baud |= CO_BAUD_10;
	val = config_get(cfg, "DeviceInfo", "BaudRate_20");
	if (val && *val && strtoul(val, NULL, 0))
		baud |= CO_BAUD_20;
	val = config_get(cfg, "DeviceInfo", "BaudRate_50");
	if (val && *val && strtoul(val, NULL, 0))
		baud |= CO_BAUD_50;
	val = config_get(cfg, "DeviceInfo", "BaudRate_125");
	if (val && *val && strtoul(val, NULL, 0))
		baud |= CO_BAUD_125;
	val = config_get(cfg, "DeviceInfo", "BaudRate_250");
	if (val && *val && strtoul(val, NULL, 0))
		baud |= CO_BAUD_250;
	val = config_get(cfg, "DeviceInfo", "BaudRate_500");
	if (val && *val && strtoul(val, NULL, 0))
		baud |= CO_BAUD_500;
	val = config_get(cfg, "DeviceInfo", "BaudRate_800");
	if (val && *val && strtoul(val, NULL, 0))
		baud |= CO_BAUD_800;
	val = config_get(cfg, "DeviceInfo", "BaudRate_1000");
	if (val && *val && strtoul(val, NULL, 0))
		baud |= CO_BAUD_1000;
	co_dev_set_baud(dev, baud);

	val = config_get(cfg, "DeviceInfo", "LSS_Supported");
	if (val && *val)
		co_dev_set_lss(dev, strtoul(val, NULL, 0));

	// For each of the basic data types, check whether it is supported for
	// mapping dummy entries in PDOs.
	co_unsigned32_t dummy = 0;
	for (int i = 0; i < 0x20; i++) {
		// Create the key name.
		char key[10];
		sprintf(key, "Dummy%04X", (co_unsigned16_t)i);

		val = config_get(cfg, "DummyUsage", key);
		if (val && *val && strtoul(val, NULL, 0))
			dummy |= 1u << i;
	}
	co_dev_set_dummy(dev, dummy);

	// Count the total number of objects.
	co_unsigned16_t n = 0;
	n += config_get_idx(cfg, "MandatoryObjects", 0, NULL);
	n += config_get_idx(cfg, "OptionalObjects", 0, NULL);
	n += config_get_idx(cfg, "ManufacturerObjects", 0, NULL);

	// Parse the object indices.
	co_unsigned16_t *idx = malloc(n * sizeof(co_unsigned16_t));
	if (!idx) {
		diag(DIAG_ERROR, errno2c(errno),
				"unable to create object list");
		goto error_parse_idx;
	}
	co_unsigned16_t i = 0;
	i += config_get_idx(cfg, "MandatoryObjects", n - i, idx + i);
	i += config_get_idx(cfg, "OptionalObjects", n - i, idx + i);
	config_get_idx(cfg, "ManufacturerObjects", n - i, idx + i);

	for (i = 0; i < n; i++) {
		if (!idx[i]) {
			diag(DIAG_ERROR, 0, "entry (%d) missing in object list",
					i);
			goto error_parse_obj;
		}

		// Create the section name for the object.
		char section[5];
		sprintf(section, "%X", idx[i]);

		// Create the object and add it to the dictionary.
		co_obj_t *obj = co_obj_build(dev, idx[i]);
		if (!obj)
			goto error_parse_obj;

		// Parse the configuration section for the object.
		if (co_obj_parse_cfg(obj, cfg, section) == -1)
			goto error_parse_obj;
	}

	if (!co_dev_find_obj(dev, 0x1000))
		diag(DIAG_WARNING, 0, "mandatory object 0x1000 missing");
	if (!co_dev_find_obj(dev, 0x1001))
		diag(DIAG_WARNING, 0, "mandatory object 0x1001 missing");
	if (!co_dev_find_obj(dev, 0x1018))
		diag(DIAG_WARNING, 0, "mandatory object 0x1018 missing");

	// Parse compact PDO definitions after the explicit object definitions
	// to prevent overwriting PDOs.
	val = config_get(cfg, "DeviceInfo", "CompactPDO");
	if (val && *val) {
		unsigned int mask = strtoul(val, NULL, 0);

		co_unsigned16_t nrpdo = 0;
		val = config_get(cfg, "DeviceInfo", "NrOfRxPDO");
		if (val && *val)
			nrpdo = (co_unsigned16_t)strtoul(val, NULL, 0);
		for (co_unsigned16_t num = 1; num <= nrpdo; num++) {
			if (co_rpdo_build(dev, num, mask) == -1)
				goto error_parse_pdo;
		}

		co_unsigned16_t ntpdo = 0;
		val = config_get(cfg, "DeviceInfo", "NrOfTxPDO");
		if (val && *val)
			ntpdo = (co_unsigned16_t)strtoul(val, NULL, 0);
		for (co_unsigned16_t num = 1; num <= ntpdo; num++) {
			if (co_tpdo_build(dev, num, mask) == -1)
				goto error_parse_pdo;
		}
	}

	val = config_get(cfg, "DeviceComissioning", "NodeID");
	// clang-format off
	if (val && *val && co_dev_set_id(dev,
			(co_unsigned8_t)strtoul(val, NULL, 0)) == -1) {
		// clang-format on
		diag(DIAG_ERROR, get_errc(), "invalid node-ID (%s) specified",
				val);
		goto error_parse_dcf;
	}

	val = config_get(cfg, "DeviceComissioning", "NetNumber");
	// clang-format off
	if (val && *val && co_dev_set_netid(dev,
			(co_unsigned32_t)strtoul(val, NULL, 0)) == -1) {
		// clang-format on
		diag(DIAG_ERROR, get_errc(),
				"invalid network-ID (%s) specified", val);
		goto error_parse_dcf;
	}

	// clang-format off
	if (co_dev_set_name(dev,
			config_get(cfg, "DeviceComissioning", "NodeName"))
			== -1) {
		// clang-format on
		diag(DIAG_ERROR, get_errc(), "unable to set node name");
		goto error_parse_dcf;
	}

	val = config_get(cfg, "DeviceComissioning", "Baudrate");
	if (val && *val)
		co_dev_set_rate(dev, (co_unsigned16_t)strtoul(val, NULL, 0));

	val = config_get(cfg, "DeviceComissioning", "LSS_SerialNumber");
	// clang-format off
	if (val && *val && !co_dev_set_val_u32(dev, 0x1018, 0x04,
			strtoul(val, NULL, 0))) {
		// clang-format on
		diag(DIAG_ERROR, get_errc(), "unable to set serial number");
		goto error_parse_dcf;
	}

	free(idx);

	return 0;

error_parse_pdo:
error_parse_dcf:
error_parse_obj:
	free(idx);
error_parse_idx:
error_parse_dev:
	return -1;
}

static int
co_obj_parse_cfg(co_obj_t *obj, const config_t *cfg, const char *section)
{
	assert(obj);
	assert(cfg);

	const char *val;
	struct floc at = { section, 0, 0 };

	co_unsigned16_t idx = co_obj_get_idx(obj);

	const char *name = config_get(cfg, section, "ParameterName");
	if (!name || !*name) {
		diag(DIAG_ERROR, 0,
				"ParameterName not specified for object 0x%04X",
				idx);
		return -1;
	}
#ifndef LELY_NO_CO_OBJ_NAME
	val = config_get(cfg, section, "Denotation");
	if (val && *val)
		name = val;
	if (co_obj_set_name(obj, name) == -1) {
		diag(DIAG_ERROR, get_errc(),
				"unable to set name of object 0x%04X", idx);
		return -1;
	}
#endif

	co_unsigned8_t code = co_obj_get_code(obj);
	val = config_get(cfg, section, "ObjectType");
	if (val && *val) {
		code = (co_unsigned8_t)strtoul(val, NULL, 0);
		if (co_obj_set_code(obj, code) == -1) {
			diag(DIAG_ERROR, 0,
					"ObjectType = 0x%x for object 0x%04X",
					code, idx);
			return -1;
		}
	}

	if (code == CO_OBJECT_DEFSTRUCT || code == CO_OBJECT_ARRAY
			|| code == CO_OBJECT_RECORD) {
		co_unsigned8_t subnum = 0;
		val = config_get(cfg, section, "SubNumber");
		if (val && *val)
			subnum = (co_unsigned8_t)strtoul(val, NULL, 0);
		co_unsigned8_t subobj = 0;
		val = config_get(cfg, section, "CompactSubObj");
		if (val && *val)
			subobj = (co_unsigned8_t)strtoul(val, NULL, 0);
		if (!subnum && !subobj) {
			diag(DIAG_ERROR, 0,
					"neither SubNumber nor CompactSubObj specified for object 0x%04X",
					idx);
			return -1;
		}
		if (subnum && subobj) {
			diag(DIAG_ERROR, 0,
					"both SubNumber and CompactSubObj specified for object 0x%04X",
					idx);
			return -1;
		}

		// Parse the sub-objects specified by SubNumber.
		for (size_t subidx = 0; subnum && subidx < 0xff; subidx++) {
			// Create section name for the sub-object.
			char section[10];
			sprintf(section, "%Xsub%X", (co_unsigned16_t)idx,
					(co_unsigned8_t)subidx);

			// Check whether the sub-index exists by checking the
			// presence of the mandatory ParameterName keyword.
			const char *name = config_get(
					cfg, section, "ParameterName");
			if (!name || !*name)
				continue;
			subnum--;

			// The Denonation entry, if it exists, overrides
			// ParameterName.
			val = config_get(cfg, section, "Denotation");
			if (val && *val)
				name = val;

			// Obtain the data type of the sub-object.
			val = config_get(cfg, section, "DataType");
			if (!val || !*val) {
				diag_at(DIAG_ERROR, 0, &at,
						"DataType not specified");
				return -1;
			}
			co_unsigned16_t type =
					(co_unsigned16_t)strtoul(val, NULL, 0);

			// Create and insert the sub-object.
			co_sub_t *sub = co_sub_build(obj,
					(co_unsigned8_t)subidx, type, name);
			if (!sub)
				return -1;

			// Parse the configuration section for the sub-object.
			if (co_sub_parse_cfg(sub, cfg, section) == -1)
				return -1;
		}

		// Create an array based on CompactSubObj.
		if (subobj) {
			co_sub_t *sub = co_sub_build(obj, 0,
					CO_DEFTYPE_UNSIGNED8, "NrOfObjects");
			if (!sub)
				return -1;
			co_val_make(sub->type, &sub->def, &subobj,
					sizeof(subobj));
			co_val_copy(sub->type, sub->val, &sub->def);
			co_sub_set_access(sub, CO_ACCESS_RO);

			name = config_get(cfg, section, "ParameterName");

			// Obtain the data type of the sub-object.
			val = config_get(cfg, section, "DataType");
			if (!val || !*val) {
				diag_at(DIAG_ERROR, 0, &at,
						"DataType not specified");
				return -1;
			}
			co_unsigned16_t type =
					(co_unsigned16_t)strtoul(val, NULL, 0);

			// Create the sub-objects.
			for (size_t subidx = 1; subidx <= subobj; subidx++) {
				// Create name of the sub-object.
				char *subname = NULL;
				// clang-format off
				if (asprintf(&subname, "%s%u", name,
						(co_unsigned8_t)subidx) < 0)
					// clang-format on
					return -1;

				// Create and insert the sub-object.
				sub = co_sub_build(obj, (co_unsigned8_t)subidx,
						type, subname);
				free(subname);
				if (!sub)
					return -1;

				// Parse the configuration section for the
				// sub-object.
				if (co_sub_parse_cfg(sub, cfg, section) == -1)
					return -1;
			}

#ifndef LELY_NO_CO_OBJ_NAME
			// Parse the names of the sub-objects.
			if (co_obj_parse_names(obj, cfg) == -1)
				return -1;
#endif

			// Parse the values of the sub-objects.
			if (co_obj_parse_values(obj, cfg) == -1)
				return -1;
		}

		co_sub_t *sub = co_obj_find_sub(obj, 0x00);
		if (!sub || co_sub_get_type(sub) != CO_DEFTYPE_UNSIGNED8) {
			diag(DIAG_ERROR, 0,
					"object 0x%04X does not provide the highest sub-index implemented",
					idx);
			return -1;
		}
	} else {
		// Obtain the data type of the object (optional for DOMAIN
		// objects).
		co_unsigned16_t type = code == CO_OBJECT_DOMAIN
				? CO_DEFTYPE_DOMAIN
				: 0;
		val = config_get(cfg, section, "DataType");
		if (val && *val)
			type = (co_unsigned16_t)strtoul(val, NULL, 0);
		if (!type) {
			diag_at(DIAG_ERROR, 0, &at, "DataType not specified");
			return -1;
		}

		// Create and insert the sub-object.
		co_sub_t *sub = co_sub_build(obj, 0, type, name);
		if (!sub)
			return -1;

		// Parse the configuration section for the sub-object.
		if (co_sub_parse_cfg(sub, cfg, section) == -1)
			return -1;
	}

	return 0;
}

#ifndef LELY_NO_CO_OBJ_NAME
static int
co_obj_parse_names(co_obj_t *obj, const config_t *cfg)
{
	assert(obj);
	assert(cfg);

	co_unsigned16_t idx = co_obj_get_idx(obj);

	// Create the section name for the explicit names of the sub-objects.
	char section[9];
	sprintf(section, "%XName", idx);

	const char *val = config_get(cfg, section, "NrOfEntries");
	if (!val || !*val)
		return 0;

	co_unsigned8_t n = (co_unsigned8_t)strtoul(val, NULL, 0);
	for (size_t subidx = 1; n && subidx < 0xff; subidx++) {
		char key[4];
		sprintf(key, "%u", (co_unsigned8_t)subidx);

		val = config_get(cfg, section, key);
		if (val && *val) {
			n--;
			co_sub_t *sub = co_obj_find_sub(
					obj, (co_unsigned8_t)subidx);
			if (sub && co_sub_set_name(sub, val) == -1) {
				diag(DIAG_ERROR, get_errc(),
						"unable to set name of sub-object %Xsub%X",
						(co_unsigned16_t)idx,
						(co_unsigned8_t)subidx);
				return -1;
			}
		}
	}

	return 0;
}
#endif // LELY_NO_CO_OBJ_NAME

static int
co_obj_parse_values(co_obj_t *obj, const config_t *cfg)
{
	assert(obj);
	assert(cfg);

	co_unsigned8_t id = co_dev_get_id(co_obj_get_dev(obj));
	co_unsigned16_t idx = co_obj_get_idx(obj);

	// Create the section name for the explicit values of the sub-objects.
	char section[10];
	sprintf(section, "%XValue", (co_unsigned16_t)idx);
	struct floc at = { section, 0, 0 };

	const char *val = config_get(cfg, section, "NrOfEntries");
	if (!val || !*val)
		return 0;

	co_unsigned8_t n = (co_unsigned8_t)strtoul(val, NULL, 0);
	for (size_t subidx = 1; n && subidx < 0xff; subidx++) {
		char key[4];
		sprintf(key, "%u", (co_unsigned8_t)subidx);

		val = config_get(cfg, section, key);
		if (val && *val) {
			n--;
			co_sub_t *sub = co_obj_find_sub(
					obj, (co_unsigned8_t)subidx);
			co_unsigned16_t type = co_sub_get_type(sub);
			co_val_fini(type, sub->val);
			if (!strncmp(val, "$NODEID", 7)) {
				val += 7;
				sub->flags |= CO_OBJ_FLAGS_VAL_NODEID;
			}
			if (!co_val_lex(type, sub->val, val, NULL, &at)) {
				diag(DIAG_ERROR, get_errc(),
						"unable to set value of sub-object %Xsub%X",
						(co_unsigned16_t)idx,
						(co_unsigned8_t)subidx);
				return -1;
			}
			if (sub->flags & CO_OBJ_FLAGS_VAL_NODEID)
				co_val_set_id(type, sub->val, id);
		}
	}

	return 0;
}

static co_obj_t *
co_obj_build(co_dev_t *dev, co_unsigned16_t idx)
{
	assert(dev);

	co_obj_t *obj = co_obj_create(idx);
	if (!obj) {
		diag(DIAG_ERROR, get_errc(), "unable to create object 0x%04X",
				idx);
		return NULL;
	}

	if (co_dev_insert_obj(dev, obj) == -1) {
		diag(DIAG_ERROR, 0,
				"unable to insert object 0x%04X into the object dictionary",
				idx);
		co_obj_destroy(obj);
		return NULL;
	}

	return obj;
}

static int
co_sub_parse_cfg(co_sub_t *sub, const config_t *cfg, const char *section)
{
	assert(sub);
	assert(cfg);

	const char *val;
	struct floc at = { section, 0, 0 };

	co_unsigned8_t id = co_dev_get_id(co_obj_get_dev(co_sub_get_obj(sub)));
	co_unsigned16_t type = co_sub_get_type(sub);

#ifndef LELY_NO_CO_OBJ_LIMITS
	val = config_get(cfg, section, "LowLimit");
	if (val && *val) {
		if (!strncmp(val, "$NODEID", 7)) {
			val += 7;
			sub->flags |= CO_OBJ_FLAGS_MIN_NODEID;
		}
		if (!co_val_lex(type, &sub->min, val, NULL, &at)) {
			diag_at(DIAG_ERROR, get_errc(), &at,
					"unable to parse LowLimit");
			return -1;
		}
		if (sub->flags & CO_OBJ_FLAGS_MIN_NODEID)
			co_val_set_id(type, &sub->min, id);
	}

	val = config_get(cfg, section, "HighLimit");
	if (val && *val) {
		if (!strncmp(val, "$NODEID", 7)) {
			val += 7;
			sub->flags |= CO_OBJ_FLAGS_MAX_NODEID;
		}
		if (!co_val_lex(type, &sub->max, val, NULL, &at)) {
			diag_at(DIAG_ERROR, get_errc(), &at,
					"unable to parse HighLimit");
			return -1;
		}
		if (sub->flags & CO_OBJ_FLAGS_MAX_NODEID)
			co_val_set_id(type, &sub->max, id);
	}
#endif // LELY_NO_CO_OBJ_LIMITS

	unsigned int access = co_sub_get_access(sub);
	val = config_get(cfg, section, "AccessType");
	if (val && *val) {
		if (!strcasecmp(val, "ro")) {
			access = CO_ACCESS_RO;
		} else if (!strcasecmp(val, "wo")) {
			access = CO_ACCESS_WO;
		} else if (!strcasecmp(val, "rw")) {
			access = CO_ACCESS_RW;
		} else if (!strcasecmp(val, "rwr")) {
			access = CO_ACCESS_RWR;
		} else if (!strcasecmp(val, "rww")) {
			access = CO_ACCESS_RWW;
		} else if (!strcasecmp(val, "const")) {
			access = CO_ACCESS_CONST;
		} else {
			diag_at(DIAG_ERROR, 0, &at, "AccessType = %s", val);
			return -1;
		}
		co_sub_set_access(sub, access);
	} else if (type != CO_DEFTYPE_DOMAIN) {
		diag_at(DIAG_ERROR, 0, &at, "AccessType not specified");
		return -1;
	}

	val = config_get(cfg, section, "DefaultValue");
	if (val && *val) {
		if (!strncmp(val, "$NODEID", 7)) {
			val += 7;
			sub->flags |= CO_OBJ_FLAGS_DEF_NODEID;
		}
		if (!co_val_lex(type, &sub->def, val, NULL, &at)) {
			diag_at(DIAG_ERROR, get_errc(), &at,
					"unable to parse DefaultValue");
			return -1;
		}
		if (sub->flags & CO_OBJ_FLAGS_DEF_NODEID)
			co_val_set_id(type, &sub->def, id);
	}

	val = config_get(cfg, section, "PDOMapping");
	if (val && *val)
		co_sub_set_pdo_mapping(sub, strtoul(val, NULL, 0));

	val = config_get(cfg, section, "ObjFlags");
	if (val && *val)
		sub->flags |= strtoul(val, NULL, 0);

	val = config_get(cfg, section, "ParameterValue");
	if (val && *val) {
		if (!strncmp(val, "$NODEID", 7)) {
			val += 7;
			sub->flags |= CO_OBJ_FLAGS_VAL_NODEID;
		}
		if (!co_val_lex(type, sub->val, val, NULL, &at)) {
			diag_at(DIAG_ERROR, get_errc(), &at,
					"unable to parse ParameterValue");
			return -1;
		}
		if (sub->flags & CO_OBJ_FLAGS_VAL_NODEID)
			co_val_set_id(type, sub->val, id);
#ifndef LELY_NO_CO_OBJ_FILE
	} else if (type == CO_DEFTYPE_DOMAIN
			&& (val = config_get(cfg, section, "UploadFile"))
					!= NULL) {
		if (!(access & CO_ACCESS_READ) || (access & CO_ACCESS_WRITE)) {
			diag_at(DIAG_WARNING, 0, &at,
					"AccessType must be 'ro' or 'const' when using UploadFile");
			access |= CO_ACCESS_READ;
			access &= ~CO_ACCESS_WRITE;
			co_sub_set_access(sub, access);
		}

		sub->flags |= CO_OBJ_FLAGS_UPLOAD_FILE;
		// Store the filename instead of its contents in the object
		// dictionary.
		if (co_val_init_dom(sub->val, val, strlen(val) + 1) == -1) {
			diag_at(DIAG_ERROR, get_errc(), &at,
					"unable to parse UploadFile");
			return -1;
		}
	} else if (type == CO_DEFTYPE_DOMAIN
			&& (val = config_get(cfg, section, "DownloadFile"))
					!= NULL) {
		if ((access & CO_ACCESS_READ) || !(access & CO_ACCESS_WRITE)) {
			diag_at(DIAG_WARNING, 0, &at,
					"AccessType must be 'wo' when using DownloadFile");
			access &= ~CO_ACCESS_READ;
			access |= CO_ACCESS_WRITE;
			co_sub_set_access(sub, access);
		}
		sub->flags |= CO_OBJ_FLAGS_DOWNLOAD_FILE;
		// Store the filename instead of its contents in the object
		// dictionary.
		if (co_val_init_dom(sub->val, val, strlen(val) + 1) == -1) {
			diag_at(DIAG_ERROR, get_errc(), &at,
					"unable to parse DownloadFile");
			return -1;
		}
#endif
	} else {
		if (sub->flags & CO_OBJ_FLAGS_DEF_NODEID)
			sub->flags |= CO_OBJ_FLAGS_VAL_NODEID;
		co_val_copy(type, sub->val, &sub->def);
	}

#ifndef LELY_NO_CO_OBJ_LIMITS
	if (co_type_is_basic(type)) {
		const void *min = co_sub_addressof_min(sub);
		const void *max = co_sub_addressof_max(sub);
		const void *def = co_sub_addressof_def(sub);
		const void *val = co_sub_addressof_val(sub);
		if (co_val_cmp(type, min, max) > 0)
			diag_at(DIAG_WARNING, 0, &at,
					"LowLimit exceeds HighLimit");
		if (co_val_cmp(type, def, min) < 0)
			diag_at(DIAG_WARNING, 0, &at, "DefaultValue underflow");
		if (co_val_cmp(type, def, max) > 0)
			diag_at(DIAG_WARNING, 0, &at, "DefaultValue overflow");
		if (co_val_cmp(type, val, def)
				&& co_val_cmp(type, val, min) < 0)
			diag_at(DIAG_WARNING, 0, &at,
					"ParameterValue underflow");
		if (co_val_cmp(type, val, def)
				&& co_val_cmp(type, val, max) > 0)
			diag_at(DIAG_WARNING, 0, &at,
					"ParameterValue overflow");
	}
#endif

	return 0;
}

static co_sub_t *
co_sub_build(co_obj_t *obj, co_unsigned8_t subidx, co_unsigned16_t type,
		const char *name)
{
	assert(obj);

	co_unsigned16_t idx = co_obj_get_idx(obj);

	co_sub_t *sub = co_sub_create(subidx, type);
	if (!sub) {
		diag(DIAG_ERROR, get_errc(),
				"unable to create sub-object %Xsub%X", idx,
				subidx);
		goto error;
	}

	if (co_obj_insert_sub(obj, sub) == -1) {
		diag(DIAG_ERROR, 0,
				"unable to insert sub-object %Xsub%X into the object dictionary",
				idx, subidx);
		goto error;
	}

#ifndef LELY_NO_CO_OBJ_NAME
	if (co_sub_set_name(sub, name) == -1) {
		diag(DIAG_ERROR, get_errc(),
				"unable to set name of sub-object %Xsub%X", idx,
				subidx);
		goto error;
	}
#else
	(void)name;
#endif

	return sub;

error:
	co_sub_destroy(sub);
	return NULL;
}

static int
co_rpdo_build(co_dev_t *dev, co_unsigned16_t num, int mask)
{
	assert(dev);
	assert(num && num <= 512);

	// Find the highest sub-index supported.
	mask &= 0x3f;
	co_unsigned8_t n = 0;
	for (int i = 0; i < 6; i++) {
		if (mask & (1 << i))
			n = i + 1;
	}

	// Create the RPDO communication parameter if it does not exist.
	if (!co_dev_find_obj(dev, 0x1400 + num - 1)) {
		co_obj_t *obj = co_obj_build(dev, 0x1400 + num - 1);
		if (!obj)
			return -1;
#ifndef LELY_NO_CO_OBJ_NAME
		if (co_obj_set_name(obj, "RPDO communication parameter")
				== -1) {
			diag(DIAG_ERROR, get_errc(), "unable configure RPDO %u",
					num);
			return -1;
		}
#endif
		co_obj_set_code(obj, CO_OBJECT_RECORD);

		co_sub_t *sub = co_sub_build(obj, 0, CO_DEFTYPE_UNSIGNED8,
				"Highest sub-index supported");
		if (!sub)
			return -1;
		co_val_make(sub->type, &sub->def, &n, sizeof(n));
		co_val_copy(sub->type, sub->val, &sub->def);
		co_sub_set_access(sub, CO_ACCESS_CONST);

		if (mask & 0x01) {
			sub = co_sub_build(obj, 1, CO_DEFTYPE_UNSIGNED32,
					"COB-ID used by RPDO");
			if (!sub)
				return -1;
			co_unsigned32_t cobid = CO_PDO_COBID_VALID;
			if (num <= 4) {
				cobid = num * 0x100 + 0x100 + 0xff;
				sub->flags |= CO_OBJ_FLAGS_DEF_NODEID;
				sub->flags |= CO_OBJ_FLAGS_VAL_NODEID;
			}
			co_val_make(sub->type, &sub->def, &cobid,
					sizeof(cobid));
			co_val_copy(sub->type, sub->val, &sub->def);
			co_sub_set_access(sub, CO_ACCESS_RW);
		}

		if (mask & 0x02) {
			sub = co_sub_build(obj, 2, CO_DEFTYPE_UNSIGNED8,
					"Transmission type");
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}

		if (mask & 0x04) {
			sub = co_sub_build(obj, 3, CO_DEFTYPE_UNSIGNED16,
					"Inhibit time");
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}

		if (mask & 0x08) {
			sub = co_sub_build(obj, 4, CO_DEFTYPE_UNSIGNED8,
					"Compatibility entry");
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}

		if (mask & 0x10) {
			sub = co_sub_build(obj, 5, CO_DEFTYPE_UNSIGNED16,
					"Event timer");
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}

		if (mask & 0x20) {
			sub = co_sub_build(obj, 6, CO_DEFTYPE_UNSIGNED8,
					"SYNC start value");
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}
	}

	// Create the RPDO mapping parameter if it does not exist.
	if (!co_dev_find_obj(dev, 0x1600 + num - 1)) {
		co_obj_t *obj = co_obj_build(dev, 0x1600 + num - 1);
		if (!obj)
			return -1;
#ifndef LELY_NO_CO_OBJ_NAME
		if (co_obj_set_name(obj, "RPDO mapping parameter") == -1) {
			diag(DIAG_ERROR, get_errc(), "unable configure RPDO %u",
					num);
			return -1;
		}
#endif
		co_obj_set_code(obj, CO_OBJECT_RECORD);

		co_sub_t *sub = co_sub_build(obj, 0, CO_DEFTYPE_UNSIGNED8,
				"Highest sub-index supported");
		if (!sub)
			return -1;
		co_sub_set_access(sub, CO_ACCESS_RW);

		for (co_unsigned8_t i = 1; i <= 0x40; i++) {
			char name[22];
			sprintf(name, "Application object %u", i);

			co_sub_t *sub = co_sub_build(
					obj, i, CO_DEFTYPE_UNSIGNED32, name);
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}
	}

	return 0;
}

static int
co_tpdo_build(co_dev_t *dev, co_unsigned16_t num, int mask)
{
	assert(dev);
	assert(num && num <= 512);

	// Find the highest sub-index supported.
	mask &= 0x3f;
	co_unsigned8_t n = 0;
	for (int i = 0; i < 6; i++) {
		if (mask & (1 << i))
			n = i + 1;
	}

	// Create the TPDO communication parameter if it does not exist.
	if (!co_dev_find_obj(dev, 0x1800 + num - 1)) {
		co_obj_t *obj = co_obj_build(dev, 0x1800 + num - 1);
		if (!obj)
			return -1;
#ifndef LELY_NO_CO_OBJ_NAME
		if (co_obj_set_name(obj, "TPDO communication parameter")
				== -1) {
			diag(DIAG_ERROR, get_errc(), "unable configure TPDO %u",
					num);
			return -1;
		}
#endif
		co_obj_set_code(obj, CO_OBJECT_RECORD);

		co_sub_t *sub = co_sub_build(obj, 0, CO_DEFTYPE_UNSIGNED8,
				"Highest sub-index supported");
		if (!sub)
			return -1;
		co_val_make(sub->type, &sub->def, &n, sizeof(n));
		co_val_copy(sub->type, sub->val, &sub->def);
		co_sub_set_access(sub, CO_ACCESS_CONST);

		if (mask & 0x01) {
			sub = co_sub_build(obj, 1, CO_DEFTYPE_UNSIGNED32,
					"COB-ID used by TPDO");
			if (!sub)
				return -1;
			co_unsigned32_t cobid = CO_PDO_COBID_VALID;
			if (num <= 4) {
				cobid = num * 0x100 + 0x80 + 0xff;
				sub->flags |= CO_OBJ_FLAGS_DEF_NODEID;
				sub->flags |= CO_OBJ_FLAGS_VAL_NODEID;
			}
			co_val_make(sub->type, &sub->def, &cobid,
					sizeof(cobid));
			co_val_copy(sub->type, sub->val, &sub->def);
			co_sub_set_access(sub, CO_ACCESS_RW);
		}

		if (mask & 0x02) {
			sub = co_sub_build(obj, 2, CO_DEFTYPE_UNSIGNED8,
					"Transmission type");
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}

		if (mask & 0x04) {
			sub = co_sub_build(obj, 3, CO_DEFTYPE_UNSIGNED16,
					"Inhibit time");
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}

		if (mask & 0x08) {
			sub = co_sub_build(obj, 4, CO_DEFTYPE_UNSIGNED8,
					"Reserved");
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}

		if (mask & 0x10) {
			sub = co_sub_build(obj, 5, CO_DEFTYPE_UNSIGNED16,
					"Event timer");
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}

		if (mask & 0x20) {
			sub = co_sub_build(obj, 6, CO_DEFTYPE_UNSIGNED8,
					"SYNC start value");
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}
	}

	// Create the TPDO mapping parameter if it does not exist.
	if (!co_dev_find_obj(dev, 0x1a00 + num - 1)) {
		co_obj_t *obj = co_obj_build(dev, 0x1a00 + num - 1);
		if (!obj)
			return -1;
#ifndef LELY_NO_CO_OBJ_NAME
		if (co_obj_set_name(obj, "TPDO mapping parameter") == -1) {
			diag(DIAG_ERROR, get_errc(), "unable configure TPDO %u",
					num);
			return -1;
		}
#endif
		co_obj_set_code(obj, CO_OBJECT_RECORD);

		co_sub_t *sub = co_sub_build(obj, 0, CO_DEFTYPE_UNSIGNED8,
				"Highest sub-index supported");
		if (!sub)
			return -1;
		co_sub_set_access(sub, CO_ACCESS_RW);

		for (co_unsigned8_t i = 1; i <= 0x40; i++) {
			char name[22];
			sprintf(name, "Application object %u", i);

			co_sub_t *sub = co_sub_build(
					obj, i, CO_DEFTYPE_UNSIGNED32, name);
			if (!sub)
				return -1;
			co_sub_set_access(sub, CO_ACCESS_RW);
		}
	}

	return 0;
}

static void
co_val_set_id(co_unsigned16_t type, void *val, co_unsigned8_t id)
{
	assert(val);

	union co_val *u = val;
	switch (type) {
#define LELY_CO_DEFINE_TYPE(a, b, c, d) \
	case CO_DEFTYPE_##a: \
		u->c += id; \
		break;
#include <lely/co/def/basic.def>
#undef LELY_CO_DEFINE_TYPE
	}
}

static co_unsigned16_t
config_get_idx(const config_t *cfg, const char *section, co_unsigned16_t maxidx,
		co_unsigned16_t *idx)
{
	assert(cfg);

	if (!idx)
		maxidx = 0;

	const char *val = config_get(cfg, section, "SupportedObjects");
	if (!val || !*val)
		return 0;

	co_unsigned16_t n = (co_unsigned16_t)strtoul(val, NULL, 0);
	for (size_t i = 0; i < (size_t)MIN(n, maxidx); i++) {
		char key[6];
		sprintf(key, "%u", (co_unsigned16_t)(i + 1));

		val = config_get(cfg, section, key);
		// clang-format off
		idx[i] = val && *val
				? (co_unsigned16_t)strtoul(val, NULL, 0) : 0;
		// clang-format on
	}

	return n;
}

#endif // !LELY_NO_CO_DCF
