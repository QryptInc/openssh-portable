#include "monitor_wrap.h"
#include "qryptutils.h"
#include "ssherr.h"
#include <string.h>

#include "qryptsecurity_c.h"

static qrypt_security_t qs = NULL;
static char* saved_token = NULL;

struct qrypt_ctx {
	symmetric_key_data_t* keydata;
	key_config_t keyconfig;
};

static symmetric_key_data_t* keydata_new() {
	return calloc(1, sizeof(symmetric_key_data_t));
}

static void keydata_free(symmetric_key_data_t* keydata) {
	qrypt_security_symmetric_key_data_free(keydata);
	free(keydata);
}

static int qrypt_init_internal(const char* token) {
	qrypt_delete();
	if ((saved_token=calloc(1, strlen(token))) == NULL) {
		return SSH_ERR_ALLOC_FAIL;
	}
	strcpy(saved_token, token);
	if (qrypt_security_create(&qs) != 0 || qrypt_security_initialize(&qs, token, strlen(token))) {
		qrypt_delete();
		return SSH_ERR_QRYPT_ERROR;
	}
	return 0;
}

int qrypt_init(struct qrypt_ctx** ctx_p, const char* token) {
	int r;
	struct qrypt_ctx* ctx = NULL;
	if (qs == NULL || strcmp(saved_token, token) != 0) {
		r = qrypt_init_internal(token);
		if (r != 0) {
			return r;
		}
	}
	if ((ctx=calloc(1, sizeof(struct qrypt_ctx))) == NULL) {
		return SSH_ERR_ALLOC_FAIL;
	}
	ctx->keydata = NULL;
	ctx->keyconfig.ttl = 0;
	*ctx_p = ctx;
	return 0;
}

int qrypt_generate(struct qrypt_ctx* ctx, size_t key_len) {
	symmetric_key_data_t* kd = NULL;
	if (ctx->keydata != NULL) {
		return SSH_ERR_INTERNAL_ERROR; // This should not happen
	}
	if ((kd=keydata_new()) == NULL) {
		return SSH_ERR_ALLOC_FAIL;
	}
	// Generate key
	if (qrypt_security_gen_init_otp(&qs, kd, key_len, ctx->keyconfig) != 0 || kd->key_size != key_len) {
		keydata_free(kd);
		return SSH_ERR_QRYPT_ERROR;
	}
	ctx->keydata = kd;
	return 0;
}

int qrypt_replicate(struct qrypt_ctx* ctx, const char* metadata, size_t metadata_len) {
	int r = 0;
	symmetric_key_data_t* kd;
	if (ctx->keydata != NULL) {
		return SSH_ERR_INTERNAL_ERROR; // This should not happen
	}
	// Copy metadata to keydata
	if ((kd=keydata_new()) == NULL || (kd->metadata=calloc(1, metadata_len)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(kd->metadata, metadata, metadata_len);
	kd->metadata_size = metadata_len;
	// Replicate key
	if (qrypt_security_gen_sync(&qs, kd) != 0) {
		r = SSH_ERR_QRYPT_ERROR;
		goto out;
	}
	ctx->keydata = kd;
	kd = NULL;
out:
	keydata_free(kd);
	return r;
}

void qrypt_delete() {
	free(saved_token);
	qrypt_security_delete(&qs);
}

const char* qrypt_ctx_metadata_ptr(struct qrypt_ctx* ctx) {
	if (ctx == NULL || ctx->keydata == NULL) {
		return NULL;
	}
	return ctx->keydata->metadata;
}

size_t qrypt_ctx_metadata_len(struct qrypt_ctx* ctx){
	if (ctx == NULL || ctx->keydata == NULL) {
		return 0;
	}
	return ctx->keydata->metadata_size;
}

const char* qrypt_ctx_key_ptr(struct qrypt_ctx* ctx) {
	if (ctx == NULL || ctx->keydata == NULL) {
		return NULL;
	}
	return ctx->keydata->key;
}

size_t qrypt_ctx_key_len(struct qrypt_ctx* ctx) {
	if (ctx == NULL || ctx->keydata == NULL) {
		return 0;
	}
	return ctx->keydata->key_size;
}

void qrypt_ctx_free(struct qrypt_ctx* ctx) {
	keydata_free(ctx->keydata);
	free(ctx);
}

int ssh_qrypt_generate(struct ssh* ssh, size_t key_len, struct sshbuf** key_p, struct sshbuf** metadata_p) {
	int r;
	struct qrypt_ctx* ctx;
	struct sshbuf* key = NULL;
	struct sshbuf* metadata = NULL;
	if (use_privsep) {
#ifdef HAS_MONITOR
		// Use monitor to make sdk calls from privileged user.
		return mm_qrypt_generate(key_len, key_p, metadata_p);
#else
		// Should not happen. Return an error because sdk calls from unprivileged user will seg fault.
		return SSH_ERR_INTERNAL_ERROR;
#endif
	}
	if (qrypt_init(&ctx, ssh->qrypt_token) != 0 || qrypt_generate(ctx, key_len) != 0) {
		r = SSH_ERR_QRYPT_ERROR;
		goto out;
	}
	if ((key=sshbuf_new()) == NULL || (metadata=sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (
		(r=sshbuf_put(key, ctx->keydata->key, ctx->keydata->key_size)) != 0 ||
		(r=sshbuf_put(metadata, ctx->keydata->metadata, ctx->keydata->metadata_size)) != 0
	) {
		goto out;
	}
	*key_p = key;
	key = NULL;
	*metadata_p = metadata;
	metadata = NULL;
out:
	qrypt_ctx_free(ctx);
	sshbuf_free(key);
	sshbuf_free(metadata);
	return r;
}

int ssh_qrypt_replicate(struct ssh* ssh, const char* metadata, size_t metadata_len, struct sshbuf** key_p) {
	int r;
	struct qrypt_ctx* ctx;
	struct sshbuf* key = NULL;
	if (use_privsep) {
#ifdef HAS_MONITOR
		// Use monitor to make sdk calls from privileged user.
		return mm_qrypt_replicate(metadata, metadata_len, key_p);
#else
		// Should not happen. Return an error because sdk calls from unprivileged user will seg fault.
		return SSH_ERR_INTERNAL_ERROR;
#endif
	}
	if (qrypt_init(&ctx, ssh->qrypt_token) != 0 || qrypt_replicate(ctx, metadata, metadata_len) != 0) {
		r = SSH_ERR_QRYPT_ERROR;
		goto out;
	}
	if ((key=sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r=sshbuf_put(key, ctx->keydata->key,ctx->keydata->key_size)) != 0) {
		goto out;
	}
	*key_p = key;
	key = NULL;
out:
	qrypt_ctx_free(ctx);
	sshbuf_free(key);
	return r;
}