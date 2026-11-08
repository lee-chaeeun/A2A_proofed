/* pqtpm: bounded command-line bridge between the a2aid Go code and a TPM 2.0 v1.85
 * emulator (wolfTPM firmware TPM, socket transport) for ML-DSA identity keys.
 *
 * Every operation is a real TPM command sequence issued through the wolfTPM client
 * library (TPM2_CreatePrimary, TPM2_EvictControl, TPM2_ReadPublic,
 * TPM2_SignSequenceStart/Complete, TPM2_VerifySequenceStart/Update/Complete,
 * TPM2_FlushContext). There is no software signing fallback in this program: if the
 * emulator rejects a command, the error is reported and nothing is signed.
 *
 * Output: one JSON object on stdout; exit 0 on success, 1 on a TPM/command failure,
 * 2 on usage errors. Private key material never leaves the emulator; the only secret
 * this program handles is the key's authValue, read from a file (never printed).
 *
 * Licence: GPLv3 (this file links wolfTPM/wolfSSL, which are GPLv3-licensed).
 * Copyright 2026 Chae Eun Lee. See LICENSE in this directory.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wolftpm/tpm2_wrap.h>
#include "tpm_io.h"

#define MAX_TRACE 32
#define MAX_MSG 65536

typedef struct { const char* name; unsigned cc; int rc; long us; } traceEnt;
static traceEnt trace[MAX_TRACE];
static int ntrace;

static long now_us(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000000L + ts.tv_nsec / 1000;
}
static void tr(const char* name, unsigned cc, int rc, long t0) {
    if (ntrace < MAX_TRACE) { trace[ntrace].name = name; trace[ntrace].cc = cc; trace[ntrace].rc = rc; trace[ntrace].us = now_us() - t0; ntrace++; }
}
static void hexout(const unsigned char* b, int n) { for (int i = 0; i < n; i++) printf("%02x", b[i]); }
static int unhex(const char* s, unsigned char* out, int max) {
    int n = (int)strlen(s); if (n % 2) return -1; if (n / 2 > max) return -1;
    for (int i = 0; i < n / 2; i++) { unsigned v; if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1; out[i] = (unsigned char)v; }
    return n / 2;
}
static void print_trace(void) {
    printf("\"commands\":[");
    for (int i = 0; i < ntrace; i++) printf("%s{\"name\":\"%s\",\"cc\":\"0x%08x\",\"rc\":\"0x%x\",\"us\":%ld}", i ? "," : "", trace[i].name, trace[i].cc, (unsigned)trace[i].rc, trace[i].us);
    printf("]");
}
static int fail(const char* what, int rc) {
    printf("{\"ok\":false,\"error\":\"%s\",\"rc\":\"0x%x\",\"rc_text\":\"%s\",", what, (unsigned)rc, wolfTPM2_GetRCString(rc));
    print_trace(); printf("}\n");
    return 1;
}
static int usage(void) {
    fprintf(stderr, "usage: pqtpm [--port N] [--host H] <create|pub|sign|verify|evict|caps> [options]\n"
        "  create --persist 0x8101xxxx --auth-file F [--param 44|65|87]\n"
        "  pub    --handle 0x8101xxxx\n"
        "  sign   --handle 0x8101xxxx --auth-file F --msg-hex HEX [--ctx-hex HEX]\n"
        "  verify --handle 0x8101xxxx --msg-hex HEX --sig-hex HEX [--ctx-hex HEX]\n"
        "  evict  --handle 0x8101xxxx\n");
    return 2;
}
static int read_auth(const char* path, unsigned char* out, int max) {
    FILE* f = fopen(path, "rb"); if (!f) return -1;
    int n = (int)fread(out, 1, max, f); fclose(f);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' ')) n--;
    return n;
}

int main(int argc, char** argv) {
    const char* cmd = NULL; const char* persistS = NULL; const char* handleS = NULL; const char* authFile = NULL;
    const char* msgHex = NULL; const char* ctxHex = NULL; const char* sigHex = NULL; int param = 65;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) setenv("TPM2_SWTPM_PORT", argv[++i], 1);
        else if (!strcmp(argv[i], "--host") && i + 1 < argc) setenv("TPM2_SWTPM_HOST", argv[++i], 1);
        else if (!strcmp(argv[i], "--persist") && i + 1 < argc) persistS = argv[++i];
        else if (!strcmp(argv[i], "--handle") && i + 1 < argc) handleS = argv[++i];
        else if (!strcmp(argv[i], "--auth-file") && i + 1 < argc) authFile = argv[++i];
        else if (!strcmp(argv[i], "--msg-hex") && i + 1 < argc) msgHex = argv[++i];
        else if (!strcmp(argv[i], "--ctx-hex") && i + 1 < argc) ctxHex = argv[++i];
        else if (!strcmp(argv[i], "--sig-hex") && i + 1 < argc) sigHex = argv[++i];
        else if (!strcmp(argv[i], "--param") && i + 1 < argc) param = atoi(argv[++i]);
        else if (argv[i][0] != '-' && !cmd) cmd = argv[i];
        else return usage();
    }
    if (!cmd) return usage();
    TPMI_MLDSA_PARAMETER_SET ps = param == 44 ? TPM_MLDSA_44 : param == 87 ? TPM_MLDSA_87 : TPM_MLDSA_65;
    if (param != 44 && param != 65 && param != 87) return usage();

    static unsigned char auth[64]; int authSz = 0;
    if (authFile) { authSz = read_auth(authFile, auth, sizeof(auth)); if (authSz <= 0) { fprintf(stderr, "auth file unreadable or empty\n"); return 2; } }
    static unsigned char msg[MAX_MSG]; int msgSz = 0;
    static unsigned char ctx[256]; int ctxSz = 0;
    static unsigned char sig[5000]; int sigSz = 0;
    if (msgHex) { msgSz = unhex(msgHex, msg, sizeof(msg)); if (msgSz < 0) return usage(); }
    if (ctxHex) { ctxSz = unhex(ctxHex, ctx, sizeof(ctx)); if (ctxSz < 0) return usage(); }
    if (sigHex) { sigSz = unhex(sigHex, sig, sizeof(sig)); if (sigSz < 0) return usage(); }

    WOLFTPM2_DEV dev; WOLFTPM2_KEY key; TPMT_PUBLIC tpl; TPM_HANDLE seq = 0; int rc; long t0;
    memset(&dev, 0, sizeof(dev)); memset(&key, 0, sizeof(key)); memset(&tpl, 0, sizeof(tpl));
    t0 = now_us();
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    tr("Init(Startup/SelfTest)", 0x00000144, rc, t0);
    if (rc != TPM_RC_SUCCESS) return fail("init", rc);

    if (!strcmp(cmd, "create")) {
        if (!persistS || !authFile) return usage();
        TPM_HANDLE persist = (TPM_HANDLE)strtoul(persistS, NULL, 0);
        rc = wolfTPM2_GetKeyTemplate_MLDSA(&tpl, TPMA_OBJECT_sign | TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth | TPMA_OBJECT_noDA, ps, 0 /* no external mu */);
        if (rc != TPM_RC_SUCCESS) return fail("template", rc);
        t0 = now_us(); rc = wolfTPM2_CreatePrimaryKey(&dev, &key, TPM_RH_OWNER, &tpl, auth, authSz); tr("TPM2_CreatePrimary", TPM_CC_CreatePrimary, rc, t0);
        if (rc != TPM_RC_SUCCESS) return fail("create_primary", rc);
        t0 = now_us(); rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &key, persist); tr("TPM2_EvictControl", TPM_CC_EvictControl, rc, t0);
        if (rc != TPM_RC_SUCCESS) return fail("evict_control(persist)", rc);
        printf("{\"ok\":true,\"op\":\"create\",\"handle\":\"0x%08x\",\"alg\":\"TPM_ALG_MLDSA\",\"param_set\":%d,\"attributes\":\"0x%08x\",\"public_key_hex\":\"",
            (unsigned)key.handle.hndl, param, (unsigned)key.pub.publicArea.objectAttributes);
        hexout(key.pub.publicArea.unique.mldsa.buffer, key.pub.publicArea.unique.mldsa.size);
        printf("\",\"public_key_len\":%u,\"name_hex\":\"", (unsigned)key.pub.publicArea.unique.mldsa.size);
        hexout(key.handle.name.name, key.handle.name.size);
        printf("\",");
        print_trace(); printf("}\n");
        return 0;
    }
    if (!handleS) return usage();
    TPM_HANDLE handle = (TPM_HANDLE)strtoul(handleS, NULL, 0);
    t0 = now_us(); rc = wolfTPM2_ReadPublicKey(&dev, &key, handle); tr("TPM2_ReadPublic", TPM_CC_ReadPublic, rc, t0);
    if (rc != TPM_RC_SUCCESS) return fail("read_public", rc);
    if (key.pub.publicArea.type != TPM_ALG_MLDSA) return fail("handle is not an ML-DSA key", TPM_RC_KEY);
    if (authSz > 0) { key.handle.auth.size = (UINT16)authSz; memcpy(key.handle.auth.buffer, auth, authSz); }

    if (!strcmp(cmd, "pub")) {
        printf("{\"ok\":true,\"op\":\"pub\",\"handle\":\"0x%08x\",\"alg\":\"TPM_ALG_MLDSA\",\"param_set_id\":%u,\"attributes\":\"0x%08x\",\"public_key_hex\":\"",
            (unsigned)handle, (unsigned)key.pub.publicArea.parameters.mldsaDetail.parameterSet, (unsigned)key.pub.publicArea.objectAttributes);
        hexout(key.pub.publicArea.unique.mldsa.buffer, key.pub.publicArea.unique.mldsa.size);
        printf("\",\"public_key_len\":%u,\"name_hex\":\"", (unsigned)key.pub.publicArea.unique.mldsa.size);
        hexout(key.handle.name.name, key.handle.name.size);
        printf("\",");
        print_trace(); printf("}\n");
        return 0;
    }
    if (!strcmp(cmd, "sign")) {
        if (!msgHex || !authFile) return usage();
        int outSz = (int)sizeof(sig);
        t0 = now_us(); rc = wolfTPM2_SignSequenceStart(&dev, &key, ctxSz ? ctx : NULL, ctxSz, &seq); tr("TPM2_SignSequenceStart", TPM_CC_SignSequenceStart, rc, t0);
        if (rc != TPM_RC_SUCCESS) return fail("sign_sequence_start", rc);
        t0 = now_us(); rc = wolfTPM2_SignSequenceComplete(&dev, seq, &key, msg, msgSz, sig, &outSz); tr("TPM2_SignSequenceComplete", TPM_CC_SignSequenceComplete, rc, t0);
        if (rc != TPM_RC_SUCCESS) return fail("sign_sequence_complete", rc);
        printf("{\"ok\":true,\"op\":\"sign\",\"handle\":\"0x%08x\",\"sig_alg\":\"TPM_ALG_MLDSA\",\"msg_len\":%d,\"ctx_len\":%d,\"signature_hex\":\"", (unsigned)handle, msgSz, ctxSz);
        hexout(sig, outSz);
        printf("\",\"signature_len\":%d,", outSz);
        print_trace(); printf("}\n");
        return 0;
    }
    if (!strcmp(cmd, "verify")) {
        if (!msgHex || !sigHex) return usage();
        TPMT_TK_VERIFIED tk; memset(&tk, 0, sizeof(tk));
        t0 = now_us(); rc = wolfTPM2_VerifySequenceStart(&dev, &key, ctxSz ? ctx : NULL, ctxSz, &seq); tr("TPM2_VerifySequenceStart", 0x000001A9, rc, t0);
        if (rc != TPM_RC_SUCCESS) return fail("verify_sequence_start", rc);
        t0 = now_us(); rc = wolfTPM2_VerifySequenceUpdate(&dev, seq, msg, msgSz); tr("TPM2_SequenceUpdate", 0x0000015C, rc, t0);
        if (rc != TPM_RC_SUCCESS) return fail("sequence_update", rc);
        t0 = now_us(); rc = wolfTPM2_VerifySequenceComplete(&dev, seq, &key, NULL, 0, sig, sigSz, &tk); tr("TPM2_VerifySequenceComplete", 0x000001A3, rc, t0);
        int ok = (rc == TPM_RC_SUCCESS && tk.tag == TPM_ST_MESSAGE_VERIFIED);
        printf("{\"ok\":true,\"op\":\"verify\",\"verified\":%s,\"rc\":\"0x%x\",\"rc_text\":\"%s\",", ok ? "true" : "false", (unsigned)rc, wolfTPM2_GetRCString(rc));
        print_trace(); printf("}\n");
        return ok ? 0 : 1;
    }
    if (!strcmp(cmd, "evict")) {
        t0 = now_us(); rc = wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &key); tr("TPM2_EvictControl(delete)", TPM_CC_EvictControl, rc, t0);
        if (rc != TPM_RC_SUCCESS) return fail("evict_control(delete)", rc);
        printf("{\"ok\":true,\"op\":\"evict\",\"handle\":\"0x%08x\",", (unsigned)handle); print_trace(); printf("}\n");
        return 0;
    }
    return usage();
}
