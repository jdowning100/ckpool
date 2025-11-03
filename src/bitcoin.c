/*
 * Copyright 2014-2018,2023 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <string.h>

#include "ckpool.h"
#include "libckpool.h"
#include "bitcoin.h"
#include "stratifier.h"

static char* understood_rules[] = {"segwit"};

static bool check_required_rule(const char* rule)
{
	unsigned int i;

	for (i = 0; i < sizeof(understood_rules) / sizeof(understood_rules[0]); i++) {
		if (safecmp(understood_rules[i], rule) == 0)
			return true;
	}
	return false;
}

/* Take a bitcoin address and do some sanity checks on it, then send it to
 * bitcoind to see if it's a valid address */
bool validate_address(connsock_t *cs, const char *address, bool *script, bool *segwit)
{
	json_t *val, *res_val, *valid_val, *tmp_val;
	char rpc_req[128];
	bool ret = false;

	if (unlikely(!address)) {
		LOGWARNING("Null address passed to validate_address");
		return ret;
	}

	snprintf(rpc_req, 128, "{\"method\": \"validateaddress\", \"params\": [\"%s\"]}\n", address);
	val = json_rpc_response(cs, rpc_req);
	if (!val) {
		/* May get a parse error with an invalid address */
		LOGNOTICE("%s:%s Failed to get valid json response to validate_address %s",
			  cs->url, cs->port, address);
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGERR("Failed to get result json response to validate_address");
		goto out;
	}
	valid_val = json_object_get(res_val, "isvalid");
	if (!valid_val) {
		LOGERR("Failed to get isvalid json response to validate_address");
		goto out;
	}
	if (!json_is_true(valid_val)) {
		LOGDEBUG("Bitcoin address %s is NOT valid", address);
		goto out;
	}
	ret = true;
	tmp_val = json_object_get(res_val, "isscript");
	if (unlikely(!tmp_val)) {
		/* All recent bitcoinds with wallet support built in should
		 * support this, if not, look for addresses the braindead way
		 * to tell if it's a script address. */
		LOGDEBUG("No isscript support from bitcoind");
		if (address[0] == '3' || address[0] == '2')
			*script = true;
		/* Now look to see this isn't a bech32: We can't support
		 * bech32 without knowing if it's a pubkey or a script */
		else if (address[0] != '1' && address[0] != 'm')
			ret = false;
		goto out;
	}
	*script = json_is_true(tmp_val);
	tmp_val = json_object_get(res_val, "iswitness");
	if (unlikely(!tmp_val))
		goto out;
	*segwit = json_is_true(tmp_val);
	LOGDEBUG("Bitcoin address %s IS valid%s%s", address, *script ? " script" : "",
		 *segwit ? " segwit" : "");
out:
	if (val)
		json_decref(val);
	return ret;
}

json_t *validate_txn(connsock_t *cs, const char *txn)
{
	json_t *val = NULL;
	char *rpc_req;
	int len;

	if (unlikely(!txn || !strlen(txn))) {
		LOGWARNING("Null transaction passed to validate_txn");
		goto out;
	}
	len = strlen(txn) + 64;
	rpc_req = ckalloc(len);
	sprintf(rpc_req, "{\"method\": \"decoderawtransaction\", \"params\": [\"%s\"]}", txn);
	val = json_rpc_call(cs, rpc_req);
	dealloc(rpc_req);
	if (!val)
		LOGDEBUG("%s:%s Failed to get valid json response to decoderawtransaction", cs->url, cs->port);
out:
	return val;
}

static const char *gbt_req_sha = "{\"jsonrpc\": \"2.0\", \"id\": \"0\", \"method\": \"quai_getBlockTemplate\", \"params\": [{\"rules\": [\"sha\"]}]}\n";
static const char *gbt_req_scrypt = "{\"jsonrpc\": \"2.0\", \"id\": \"0\", \"method\": \"quai_getBlockTemplate\", \"params\": [{\"rules\": [\"scrypt\"]}]}\n";

/* Request getblocktemplate from bitcoind already connected with a connsock_t
 * and then summarise the information to the most efficient set of data
 * required to assemble a mining template, storing it in a gbtbase_t structure */
bool gen_gbtbase(connsock_t *cs, gbtbase_t *gbt, bool scrypt_algo)
{
	json_t *rules_array, *res_val, *val;
	const char *previousblockhash;
	char hash_swap[32], tmp[32];
	uint64_t coinbasevalue;
	const char *target;
	const char *flags;
	const char *bits;
	const char *rule;
	int version;
	int curtime;
	int height;
	int i;
	bool ret = false;

	/* Use appropriate GBT request based on algorithm */
	const char *gbt_req = scrypt_algo ? gbt_req_scrypt : gbt_req_sha;
	val = json_rpc_call(cs, gbt_req);
	if (!val) {
		LOGWARNING("%s:%s Failed to get valid json response to quai_getBlockTemplate", cs->url, cs->port);
		return ret;
	}

	/* Log the full JSON response from quai_getBlockTemplate */
	char *json_str = json_dumps(val, JSON_INDENT(2) | JSON_PRESERVE_ORDER);
	if (json_str) {
		LOGNOTICE("quai_getBlockTemplate JSON response:\n%s", json_str);
		free(json_str);
	}

	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to quai_getBlockTemplate");
		goto out;
	}

	rules_array = json_object_get(res_val, "rules");
	if (rules_array) {
		int rule_count =  json_array_size(rules_array);

		for (i = 0; i < rule_count; i++) {
			rule = json_string_value(json_array_get(rules_array, i));
			if (rule && *rule++ == '!' && !check_required_rule(rule)) {
				LOGERR("Required rule not understood: %s", rule);
				goto out;
			}
		}
	}

	previousblockhash = json_string_value(json_object_get(res_val, "previousblockhash"));
	target = json_string_value(json_object_get(res_val, "target"));
	version = json_integer_value(json_object_get(res_val, "version"));
	curtime = json_integer_value(json_object_get(res_val, "curtime"));
	bits = json_string_value(json_object_get(res_val, "bits"));
	height = json_integer_value(json_object_get(res_val, "height"));
	coinbasevalue = json_integer_value(json_object_get(res_val, "coinbasevalue"));

	/* New: Stratum-style pieces straight from Quai GBT */
	const char *coinb1 = json_string_value(json_object_get(res_val, "coinb1"));
	const char *coinb2 = json_string_value(json_object_get(res_val, "coinb2"));
	int en1 = json_integer_value(json_object_get(res_val, "extranonce1Length"));
	int en2 = json_integer_value(json_object_get(res_val, "extranonce2Length"));
	if (!coinb1 || !coinb2) {
		LOGERR("GBT missing coinb1/coinb2 – cannot build coinbase");
		goto out;
	}
	/* Persist helper lengths; default to 4/8 if absent */
	if (!en1) en1 = 4;
	if (!en2) en2 = 8;
	json_object_set_new_nocheck(res_val, "coinb1len", json_integer((int)strlen(coinb1) / 2));
	json_object_set_new_nocheck(res_val, "coinb2len", json_integer((int)strlen(coinb2) / 2));
	json_object_set_new_nocheck(res_val, "extranonce1Length", json_integer(en1));
	json_object_set_new_nocheck(res_val, "extranonce2Length", json_integer(en2));

	/* Store coinb1 and coinb2 hex strings in gbt structure for change detection */
	gbt->coinb1len = strlen(coinb1) / 2;
	gbt->coinb1 = strdup(coinb1);
	gbt->coinb2len = strlen(coinb2) / 2;
	gbt->coinb2 = strdup(coinb2);

	flags = "";

	if (unlikely(!previousblockhash || !target || !version || !curtime || !bits)) {
		LOGERR("JSON failed to decode GBT %s %s %d %d %s", previousblockhash, target, version, curtime, bits);
		goto out;
	}

	/* Store getblocktemplate for remainder of json components as is */
	json_incref(res_val);
	json_object_del(val, "result");
	gbt->json = res_val;

	hex2bin(hash_swap, previousblockhash, 32);
	swap_256(tmp, hash_swap);
	__bin2hex(gbt->prevhash, tmp, 32);

	strncpy(gbt->target, target, 65);

	hex2bin(hash_swap, target, 32);
	bswap_256(tmp, hash_swap);
	if (scrypt_algo)
		gbt->diff = diff_from_target_scrypt((uchar *)tmp);
	else
		gbt->diff = diff_from_target((uchar *)tmp);
	json_object_set_new_nocheck(gbt->json, "diff", json_real(gbt->diff));


	gbt->version = version;

	gbt->curtime = curtime;

	snprintf(gbt->ntime, 9, "%08x", curtime);
	json_object_set_new_nocheck(gbt->json, "ntime", json_string_nocheck(gbt->ntime));
	sscanf(gbt->ntime, "%x", &gbt->ntime32);

	snprintf(gbt->bbversion, 9, "%08x", version);
	json_object_set_new_nocheck(gbt->json, "bbversion", json_string_nocheck(gbt->bbversion));

	snprintf(gbt->nbit, 9, "%s", bits);
	json_object_set_new_nocheck(gbt->json, "nbit", json_string_nocheck(gbt->nbit));

	gbt->coinbasevalue = coinbasevalue;

	gbt->height = height;

	gbt->flags = strdup(flags);

	ret = true;
out:
	json_decref(val);
	return ret;
}

void clear_gbtbase(gbtbase_t *gbt)
{
	free(gbt->flags);
	free(gbt->coinbaseaux);
	free(gbt->coinbaseaux_bin);
	free(gbt->payoutscript);
	free(gbt->payoutscript_bin);
	if (gbt->json)
		json_decref(gbt->json);
	memset(gbt, 0, sizeof(gbtbase_t));
}

static const char *blockcount_req = "{\"method\": \"getblockcount\"}\n";

/* Request getblockcount from bitcoind, returning the count or -1 if the call
 * fails. */
int get_blockcount(connsock_t *cs)
{
	json_t *val, *res_val;
	int ret = -1;

	val = json_rpc_call(cs, blockcount_req);
	if (!val) {
		LOGWARNING("%s:%s Failed to get valid json response to getblockcount", cs->url, cs->port);
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getblockcount");
		goto out;
	}
	ret = json_integer_value(res_val);
out:
	json_decref(val);
	return ret;
}

/* Request getblockhash from bitcoind for height, writing the value into *hash
 * which should be at least 65 bytes long since the hash is 64 chars. */
bool get_blockhash(connsock_t *cs, int height, char *hash)
{
	json_t *val, *res_val;
	const char *res_ret;
	char rpc_req[128];
	bool ret = false;

	sprintf(rpc_req, "{\"method\": \"getblockhash\", \"params\": [%d]}\n", height);
	val = json_rpc_call(cs, rpc_req);
	if (!val) {
		LOGWARNING("%s:%s Failed to get valid json response to getblockhash", cs->url, cs->port);
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getblockhash");
		goto out;
	}
	res_ret = json_string_value(res_val);
	if (!res_ret || !strlen(res_ret)) {
		LOGWARNING("Got null string in result to getblockhash");
		goto out;
	}
	strncpy(hash, res_ret, 65);
	ret = true;
out:
	json_decref(val);
	return ret;
}

static const char *bestblockhash_req = "{\"method\": \"getbestblockhash\"}\n";

/* Request getbestblockhash from bitcoind. bitcoind 0.9+ only */
bool get_bestblockhash(connsock_t *cs, char *hash)
{
	json_t *val, *res_val;
	const char *res_ret;
	bool ret = false;

	/* Skip for btcsolo mode - Quai provides previousblockhash in GBT */
	if (cs->ckp && cs->ckp->btcsolo) {
		/* Return dummy hash - not used in btcsolo */
		strcpy(hash, "0000000000000000000000000000000000000000000000000000000000000000");
		return true;
	}

	val = json_rpc_call(cs, bestblockhash_req);
	if (!val) {
		LOGWARNING("%s:%s Failed to get valid json response to getbestblockhash", cs->url, cs->port);
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getbestblockhash");
		goto out;
	}
	res_ret = json_string_value(res_val);
	if (!res_ret || !strlen(res_ret)) {
		LOGWARNING("Got null string in result to getbestblockhash");
		goto out;
	}
	strncpy(hash, res_ret, 65);
	ret = true;
out:
	json_decref(val);
	return ret;
}

bool submit_block(connsock_t *cs, const char *params, bool scrypt_algo)
{
	json_t *val, *res_val;
	int len, retries = 0;
	const char *res_ret;
	bool ret = false;
	char *rpc_req;
	const char *method = scrypt_algo ? "quai_submitScryptBlock" : "quai_submitShaBlock";

	len = strlen(params) + 150;  // Increased buffer for JSON wrapper and method name
retry:
	rpc_req = ckalloc(len);
	sprintf(rpc_req, "{\"jsonrpc\": \"2.0\", \"id\": \"0\", \"method\": \"%s\", \"params\": [\"0x%s\"]}\n", method, params);
	LOGNOTICE("Submitting %s block: 0x%s", scrypt_algo ? "Scrypt" : "SHA256", params);
	val = json_rpc_call(cs, rpc_req);
	dealloc(rpc_req);
	if (!val) {
		LOGWARNING("%s:%s Failed to get valid json response to %s", cs->url, cs->port, method);
		if (++retries < 5)
			goto retry;
		return ret;
	}
	/* Log the full response for debugging */
	char *response_str = json_dumps(val, JSON_INDENT(2));
	LOGNOTICE("%s response: %s", method, response_str);
	free(response_str);

	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to %s", method);
		if (++retries < 5) {
			json_decref(val);
			goto retry;
		}
		goto out;
	}
	if (!json_is_null(res_val)) {
		res_ret = json_string_value(res_val);
		if (res_ret && strlen(res_ret)) {
			LOGWARNING("SUBMIT BLOCK RETURNED: %s", res_ret);
			/* Consider duplicate response as an accepted block */
			if (safecmp(res_ret, "duplicate"))
				goto out;
		} else {
			LOGWARNING("SUBMIT BLOCK GOT NO RESPONSE!");
			goto out;
		}
	}
	LOGWARNING("BLOCK ACCEPTED!");
	ret = true;
out:
	json_decref(val);
	return ret;
}

void precious_block(connsock_t *cs, const char *params)
{
	char *rpc_req;
	int len;

	if (unlikely(!cs->alive)) {
		LOGDEBUG("Failed to submit_txn due to connsock dead");
		return;
	}

	len = strlen(params) + 64;
	rpc_req = ckalloc(len);
	sprintf(rpc_req, "{\"method\": \"preciousblock\", \"params\": [\"%s\"]}\n", params);
	json_rpc_msg(cs, rpc_req);
	dealloc(rpc_req);
}

void submit_txn(connsock_t *cs, const char *params)
{
	char *rpc_req;
	int len;

	if (unlikely(!cs->alive)) {
		LOGDEBUG("Failed to submit_txn due to connsock dead");
		return;
	}

	len = strlen(params) + 64;
	rpc_req = ckalloc(len);
	sprintf(rpc_req, "{\"method\": \"sendrawtransaction\", \"params\": [\"%s\"]}\n", params);
	json_rpc_msg(cs, rpc_req);
	dealloc(rpc_req);
}

char *get_txn(connsock_t *cs, const char *hash)
{
	char *rpc_req, *ret = NULL;
	json_t *val, *res_val;

	if (unlikely(!cs->alive)) {
		LOGDEBUG("Failed to get_txn due to connsock dead");
		goto out;
	}

	ASPRINTF(&rpc_req, "{\"method\": \"getrawtransaction\", \"params\": [\"%s\"]}\n", hash);
	val = json_rpc_response(cs, rpc_req);
	dealloc(rpc_req);
	if (!val) {
		LOGDEBUG("%s:%s Failed to get valid json response to get_txn", cs->url, cs->port);
		goto out;
	}
	res_val = json_object_get(val, "result");
	if (res_val && !json_is_null(res_val) && json_is_string(res_val)) {
		ret = strdup(json_string_value(res_val));
		LOGDEBUG("get_txn for hash %s got data %s", hash, ret);
	} else
		LOGDEBUG("get_txn did not retrieve data for hash %s", hash);
	json_decref(val);
out:
	return ret;
}
