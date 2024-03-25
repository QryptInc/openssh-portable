#ifndef QRYPTUTILS_H
#define QRYPTUTILS_H

#include <sys/types.h>
#include <stdlib.h>
#include "packet.h"
#include "sshbuf.h"

struct qrypt_ctx;

/*
 * Allocates an empty qrypt context and instantiates the qrypt sdk if it is not 
 * already initialized (or if the token has changed from last call).
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
int qrypt_init(struct qrypt_ctx** ctx, const char* token);

/*
 * Generate a token of the specified length and store it in ctx.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
int qrypt_generate(struct qrypt_ctx* ctx, size_t key_len);

/*
 * Replicate the token associated with the specified metadata, and store it in ctx
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
int qrypt_replicate(struct qrypt_ctx* ctx, const char* metadata, size_t metadata_len);

/*
 * Delete the sdk instance and release any internal threads/memory
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
void qrypt_delete();

/* Access read-only data stored in the qrypt_ctx */
const char* qrypt_ctx_metadata_ptr(struct qrypt_ctx* ctx);
size_t qrypt_ctx_metadata_len(struct qrypt_ctx* ctx);
const char* qrypt_ctx_key_ptr(struct qrypt_ctx* ctx);
size_t qrypt_ctx_key_len(struct qrypt_ctx* ctx);

/*
 * Free any allocated memory associated with the specified ctx
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
void qrypt_ctx_free(struct qrypt_ctx* ctx);

/*
 * Oneshot function that performs the entire generate process, storing the
 * results in the provided sshbuf pointers.
 * Safe to call from a privsep context.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
int ssh_qrypt_generate(struct ssh* ssh, size_t key_len, struct sshbuf** key_buf, struct sshbuf** metadata_buf);

/*
 * Oneshot function that performs the entire replicate process, storing the
 * results in the provided sshbuf pointers.
 * Safe to call from a privsep context.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
int ssh_qrypt_replicate(struct ssh* ssh, const char* metadata, size_t metadata_len, struct sshbuf** key_buf);

#endif /* QRYPTUTILS_H */