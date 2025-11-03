/*
 * Copyright 2014-2017,2023 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef STRATIFIER_H
#define STRATIFIER_H

/* Generic structure for both workbase in stratifier and gbtbase in generator */
struct genwork {
	/* Hash table data */
	UT_hash_handle hh;

	/* The next two fields need to be consecutive as both of them are
	 * used as the key for their hashtable entry in remote_workbases */
	int64_t id;
	/* The client id this workinfo came from if remote */
	int64_t client_id;

	char idstring[20];

	/* How many readers we currently have of this workbase, set
	 * under write workbase_lock */
	int readcount;

	/* The id a remote workinfo is mapped to locally */
	int64_t mapped_id;

	ts_t gentime;
	tv_t retired;

	/* GBT/shared variables */
	char target[68];
	double diff;
	double network_diff;
	double share_diff;  /* Minimum difficulty for share submission (from GBT target field) */
	bool scrypt_algo;   /* true for Scrypt (Litecoin), false for SHA256d (Bitcoin) */
	bool block_submitted; /* Has a block already been submitted for this job? */
	uint32_t version;
	uint32_t curtime;
	char prevhash[68];
	char ntime[12];
	uint32_t ntime32;
	char bbversion[12];
	char nbit[12];
	uint64_t coinbasevalue;
	int height;
	char *flags;
	int txns;
	char *txn_data;
	char *txn_hashes;
	char witnessdata[80]; //null-terminated ascii
	bool insert_witness;
	int merkles;
	char merklehash[16][68];
	char merklebin[16][32];
	json_t *merkle_array;

	/* Quai-specific fields from getBlockTemplate */
	char *coinbaseaux;       // Pre-constructed scriptSig from go-quai (hex string) - DEPRECATED
	uchar *coinbaseaux_bin;  // Binary version of coinbaseaux - DEPRECATED
	int coinbaseaux_len;     // Length of binary coinbaseaux - DEPRECATED
	char *payoutscript;      // scriptPubKey for coinbase output (hex string) - DEPRECATED
	uchar *payoutscript_bin; // Binary version of payoutscript - DEPRECATED
	int payoutscript_len;    // Length of binary payoutscript - DEPRECATED

	/* New Quai stratum-style fields from getBlockTemplate */
	char *gbt_coinb1;        // Pre-constructed coinbase1 from go-quai (hex string)
	uchar *gbt_coinb1_bin;   // Binary version of coinb1
	int gbt_coinb1_len;      // Length of binary coinb1
	char *gbt_coinb2;        // Pre-constructed coinbase2 from go-quai (hex string)
	uchar *gbt_coinb2_bin;   // Binary version of coinb2
	int gbt_coinb2_len;      // Length of binary coinb2
	int extranonce1_len;     // Length of extranonce1 field (4 bytes)
	int extranonce2_len;     // Length of extranonce2 field (8 bytes)
	int coinbase_aux_extra_bytes_len; // Length of extra bytes in coinb2 (32 bytes)

	/* Template variables, lengths are binary lengths! */
	char *coinb1; // coinbase1
	uchar *coinb1bin;
	int coinb1len; // length of above

	char enonce1const[32]; // extranonce1 section that is constant
	uchar enonce1constbin[16];
	int enonce1constlen; // length of above - usually zero unless proxying
	int enonce1varlen; // length of unique extranonce1 string for each worker - usually 8

	int enonce2varlen; // length of space left for extranonce2 - usually 8 unless proxying

	char *coinb2; // coinbase2
	uchar *coinb2bin;
	int coinb2len; // length of above
	char *coinb3bin; // coinbase3 for variable coinb2len
	int coinb3len; // length of above

	/* Cached header binary */
	char headerbin[112];

	char *logdir;

	ckpool_t *ckp;
	bool proxy; /* This workbase is proxied work */

	bool incomplete; /* This is a remote workinfo without all the txn data */

	bool coinb_parts_supplied; /* true if GBT provided coinb1 & coinb2 */

	json_t *json; /* getblocktemplate json */
};

void parse_remote_txns(ckpool_t *ckp, const json_t *val);
#define parse_upstream_txns(ckp, val) parse_remote_txns(ckp, val)
void parse_upstream_auth(ckpool_t *ckp, json_t *val);
void parse_upstream_workinfo(ckpool_t *ckp, json_t *val);
void parse_upstream_block(ckpool_t *ckp, json_t *val);
void parse_upstream_reqtxns(ckpool_t *ckp, json_t *val);
char *stratifier_stats(ckpool_t *ckp, void *data);
void _stratifier_add_recv(ckpool_t *ckp, json_t *val, const char *file, const char *func, const int line);
#define stratifier_add_recv(ckp, val) _stratifier_add_recv(ckp, val, __FILE__, __func__, __LINE__)
void *stratifier(void *arg);

#endif /* STRATIFIER_H */
