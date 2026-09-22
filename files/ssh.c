/* SSH 2.0 server on wolfCrypt. Transport (RFC 4253) with curve25519-sha256 key exchange and an ssh-ed25519 host key, password auth (RFC 4252), and one session channel with pty and shell requests (RFC 4254). Single threaded, non blocking, driven by the caller. */

#include "ssh.h"
#include "uefirt.h"
#include "config.h"
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#define MSG_DISCONNECT             1
#define MSG_IGNORE                 2
#define MSG_UNIMPLEMENTED          3
#define MSG_DEBUG                  4
#define MSG_SERVICE_REQUEST        5
#define MSG_SERVICE_ACCEPT         6
#define MSG_EXT_INFO               7
#define MSG_KEXINIT                20
#define MSG_NEWKEYS                21
#define MSG_KEXDH_INIT             30
#define MSG_KEXDH_REPLY            31
#define MSG_USERAUTH_REQUEST       50
#define MSG_USERAUTH_FAILURE       51
#define MSG_USERAUTH_SUCCESS       52
#define MSG_GLOBAL_REQUEST         80
#define MSG_REQUEST_SUCCESS        81
#define MSG_REQUEST_FAILURE        82
#define MSG_CHANNEL_OPEN           90
#define MSG_CHANNEL_OPEN_CONFIRM   91
#define MSG_CHANNEL_OPEN_FAILURE   92
#define MSG_CHANNEL_WINDOW_ADJUST  93
#define MSG_CHANNEL_DATA           94
#define MSG_CHANNEL_EXTENDED_DATA  95
#define MSG_CHANNEL_EOF            96
#define MSG_CHANNEL_CLOSE          97
#define MSG_CHANNEL_REQUEST        98
#define MSG_CHANNEL_SUCCESS        99
#define MSG_CHANNEL_FAILURE        100

#define DISC_PROTOCOL_ERROR        2
#define DISC_KEY_EXCHANGE_FAILED   3
#define DISC_MAC_ERROR             5
#define DISC_BY_APPLICATION        11
#define DISC_NO_MORE_AUTH_METHODS  14

#define SSH_MAX_PACKET        35000
#define SSH_RX_BUF            (SSH_MAX_PACKET + 256)
#define SSH_TX_BUF            (SSH_MAX_PACKET + 256)
#define SSH_PL_BUF            SSH_MAX_PACKET
#define SSH_IN_RING           65536
#define SSH_LOCAL_WINDOW      32768
#define SSH_LOCAL_MAXPKT      32768
#define SSH_DATA_CHUNK        16384
#define SSH_ACCEPT_TIMEOUT_MS 120000
#define SSH_WRITE_TIMEOUT_MS  30000
#define SSH_CLOSE_TIMEOUT_MS  2000

static const char *KEX_ALGS     = "curve25519-sha256,curve25519-sha256@libssh.org";
static const char *HOSTKEY_ALGS = "ssh-ed25519";
static const char *ENC_ALGS     = "aes128-ctr,aes256-ctr,aes192-ctr";
static const char *MAC_ALGS     = "hmac-sha2-256,hmac-sha2-512";
static const char *COMP_ALGS    = "none";

typedef enum { ST_VERSION, ST_KEX, ST_AUTH, ST_CONN, ST_CLOSED } SSH_STATE;
typedef enum { KX_IDLE, KX_WAIT_KEXINIT, KX_WAIT_DH, KX_WAIT_NEWKEYS } KEX_STATE;

typedef struct {
    Aes     aes;
    UINT8   macKey[64];
    int     macKeyLen;
    int     macLen;
    int     macType;
    BOOLEAN active;
    UINT32  seq;
} SSH_DIR;

struct SSH_CONN {
    SSH_IO_READ  rd;
    SSH_IO_WRITE wr;
    void        *ioCtx;
    SSH_AUTH_FN  auth;
    void        *authCtx;

    WC_RNG       rng;
    BOOLEAN      rngInit;
    ed25519_key  hostKey;
    BOOLEAN      hostKeyInit;
    UINT8        hostPub[32];

    SSH_STATE    state;
    KEX_STATE    kex;
    BOOLEAN      versionSent;
    char         clientVersion[256];
    UINTN        clientVersionLen;
    UINT8       *clientKexInit;
    UINTN        clientKexInitLen;
    UINT8       *serverKexInit;
    UINTN        serverKexInitLen;
    BOOLEAN      kexInitSent;
    BOOLEAN      ignoreNextKexPacket;
    int          nextEncKeyLenIn;
    int          nextEncKeyLenOut;
    int          nextMacTypeIn;
    int          nextMacTypeOut;
    UINT8        sessionId[32];
    BOOLEAN      haveSessionId;

    SSH_DIR      in;
    SSH_DIR      out;
    UINT8        pendKey[32];
    UINT8        pendIv[16];
    UINT8        pendMac[64];
    int          pendKeyLen;
    int          pendMacType;

    UINT8       *rx;
    UINTN        rxLen;
    BOOLEAN      rxHaveLen;
    UINT32       rxPktLen;
    UINT8       *tx;
    UINT8       *pl;

    UINT8       *inRing;
    UINTN        inHead;
    UINTN        inTail;
    UINT32       consumed;

    BOOLEAN      chanOpen;
    UINT32       remoteChan;
    UINT32       remoteWindow;
    UINT32       remoteMaxPkt;
    BOOLEAN      shellReady;
    BOOLEAN      remoteEof;
    BOOLEAN      closeSent;
    BOOLEAN      closeRecv;
    UINT32       cols;
    UINT32       rows;

    BOOLEAN      authenticated;
    int          authTries;
    char         user[64];
};

/* Wire format helpers */

typedef struct {
    UINT8  *p;
    UINTN   len;
    UINTN   cap;
    BOOLEAN err;
} WBUF;

typedef struct {
    const UINT8 *p;
    UINTN        len;
    UINTN        pos;
    BOOLEAN      err;
} RBUF;

static void PutU32(UINT8 *p, UINT32 v)
{
    p[0] = (UINT8)(v >> 24);
    p[1] = (UINT8)(v >> 16);
    p[2] = (UINT8)(v >> 8);
    p[3] = (UINT8)v;
}

static UINT32 GetU32(const UINT8 *p)
{
    return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) | ((UINT32)p[2] << 8) | p[3];
}

static void WInit(WBUF *b, UINT8 *p, UINTN cap)
{
    b->p = p;
    b->len = 0;
    b->cap = cap;
    b->err = FALSE;
}

static void WBytes(WBUF *b, const void *d, UINTN n)
{
    if (b->err || b->len + n > b->cap) {
        b->err = TRUE;
        return;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
}

static void WByte(WBUF *b, UINT8 v)
{
    WBytes(b, &v, 1);
}

static void WU32(WBUF *b, UINT32 v)
{
    UINT8 t[4];
    PutU32(t, v);
    WBytes(b, t, 4);
}

static void WStr(WBUF *b, const void *d, UINTN n)
{
    WU32(b, (UINT32)n);
    WBytes(b, d, n);
}

static void WCStr(WBUF *b, const char *s)
{
    WStr(b, s, strlen(s));
}

static void WMpint(WBUF *b, const UINT8 *d, UINTN n)
{
    while (n > 0 && d[0] == 0) {
        d++;
        n--;
    }
    if (n > 0 && (d[0] & 0x80) != 0) {
        WU32(b, (UINT32)n + 1);
        WByte(b, 0);
        WBytes(b, d, n);
    } else {
        WStr(b, d, n);
    }
}

static void RInit(RBUF *r, const UINT8 *p, UINTN len)
{
    r->p = p;
    r->len = len;
    r->pos = 0;
    r->err = FALSE;
}

static UINT8 RByte(RBUF *r)
{
    if (r->err || r->pos + 1 > r->len) {
        r->err = TRUE;
        return 0;
    }
    return r->p[r->pos++];
}

static UINT32 RU32(RBUF *r)
{
    UINT32 v;
    if (r->err || r->pos + 4 > r->len) {
        r->err = TRUE;
        return 0;
    }
    v = GetU32(r->p + r->pos);
    r->pos += 4;
    return v;
}

static BOOLEAN RStr(RBUF *r, const UINT8 **d, UINTN *n)
{
    UINT32 l = RU32(r);
    if (r->err || r->pos + l > r->len) {
        r->err = TRUE;
        *d = NULL;
        *n = 0;
        return FALSE;
    }
    *d = r->p + r->pos;
    *n = l;
    r->pos += l;
    return TRUE;
}

static BOOLEAN NameIs(const UINT8 *n, UINTN len, const char *s)
{
    return (BOOLEAN)(strlen(s) == len && memcmp(n, s, len) == 0);
}

static BOOLEAN ListHas(const char *list, const UINT8 *name, UINTN nameLen)
{
    while (*list != 0) {
        const char *e = list;
        while (*e != 0 && *e != ',') {
            e++;
        }
        if ((UINTN)(e - list) == nameLen && memcmp(list, name, nameLen) == 0) {
            return TRUE;
        }
        if (*e == 0) {
            break;
        }
        list = e + 1;
    }
    return FALSE;
}

/* First entry of the client list that we also support, per RFC 4253 7.1. */
static const UINT8 *PickAlg(const UINT8 *client, UINTN clientLen, const char *ours, UINTN *chosenLen)
{
    UINTN i = 0;
    while (i < clientLen) {
        UINTN j = i;
        while (j < clientLen && client[j] != ',') {
            j++;
        }
        if (ListHas(ours, client + i, j - i)) {
            *chosenLen = j - i;
            return client + i;
        }
        i = j + 1;
    }
    *chosenLen = 0;
    return NULL;
}

static UINTN FirstEntryLen(const UINT8 *list, UINTN len)
{
    UINTN i = 0;
    while (i < len && list[i] != ',') {
        i++;
    }
    return i;
}

static int EncKeyLen(const UINT8 *n, UINTN len)
{
    if (NameIs(n, len, "aes128-ctr")) {
        return 16;
    }
    if (NameIs(n, len, "aes192-ctr")) {
        return 24;
    }
    return 32;
}

static int MacType(const UINT8 *n, UINTN len)
{
    return NameIs(n, len, "hmac-sha2-512") ? WC_SHA512 : WC_SHA256;
}

static int MacLenOf(int type)
{
    return type == WC_SHA512 ? 64 : 32;
}

/* Packet layer */

static int SendPacket(SSH_CONN *c, const UINT8 *payload, UINTN len)
{
    UINTN  blk = c->out.active ? 16 : 8;
    UINTN  padLen;
    UINTN  total;
    UINTN  macLen = 0;
    UINT8 *tx = c->tx;
    UINT8  seqBe[4];

    if (c->state == ST_CLOSED || len + 64 > SSH_MAX_PACKET) {
        return -1;
    }
    padLen = blk - ((5 + len) % blk);
    if (padLen < 4) {
        padLen += blk;
    }
    total = 5 + len + padLen;
    PutU32(tx, (UINT32)(1 + len + padLen));
    tx[4] = (UINT8)padLen;
    memcpy(tx + 5, payload, len);
    if (wc_RNG_GenerateBlock(&c->rng, tx + 5 + len, (word32)padLen) != 0) {
        return -1;
    }
    if (c->out.active) {
        Hmac h;
        PutU32(seqBe, c->out.seq);
        if (wc_HmacInit(&h, NULL, INVALID_DEVID) != 0 ||
            wc_HmacSetKey(&h, c->out.macType, c->out.macKey, (word32)c->out.macKeyLen) != 0 ||
            wc_HmacUpdate(&h, seqBe, 4) != 0 ||
            wc_HmacUpdate(&h, tx, (word32)total) != 0 ||
            wc_HmacFinal(&h, tx + total) != 0) {
            wc_HmacFree(&h);
            return -1;
        }
        wc_HmacFree(&h);
        macLen = (UINTN)c->out.macLen;
        if (wc_AesCtrEncrypt(&c->out.aes, tx, tx, (word32)total) != 0) {
            return -1;
        }
    }
    c->out.seq++;
    if (gDebug) {
        Print("SSH: tx msg %u len %u\n", payload[0], (unsigned)len);
    }
    if (c->wr(c->ioCtx, tx, total + macLen) != 0) {
        c->state = ST_CLOSED;
        return -1;
    }
    return 0;
}

static void Disconnect(SSH_CONN *c, UINT32 reason, const char *msg)
{
    WBUF b;
    if (c->state == ST_CLOSED) {
        return;
    }
    WInit(&b, c->pl, SSH_PL_BUF);
    WByte(&b, MSG_DISCONNECT);
    WU32(&b, reason);
    WCStr(&b, msg);
    WCStr(&b, "");
    SendPacket(c, b.p, b.len);
    c->state = ST_CLOSED;
    Print("SSH: disconnect (%s)\n", msg);
}

static BOOLEAN CanSendNow(SSH_CONN *c)
{
    return (BOOLEAN)(c->state == ST_CONN && c->chanOpen && !c->closeSent && (c->kex == KX_IDLE || c->kex == KX_WAIT_NEWKEYS));
}

/* Key exchange */

static int SendKexInit(SSH_CONN *c)
{
    WBUF  b;
    UINT8 cookie[16];

    if (wc_RNG_GenerateBlock(&c->rng, cookie, sizeof(cookie)) != 0) {
        return -1;
    }
    WInit(&b, c->pl, SSH_PL_BUF);
    WByte(&b, MSG_KEXINIT);
    WBytes(&b, cookie, 16);
    WCStr(&b, KEX_ALGS);
    WCStr(&b, HOSTKEY_ALGS);
    WCStr(&b, ENC_ALGS);
    WCStr(&b, ENC_ALGS);
    WCStr(&b, MAC_ALGS);
    WCStr(&b, MAC_ALGS);
    WCStr(&b, COMP_ALGS);
    WCStr(&b, COMP_ALGS);
    WCStr(&b, "");
    WCStr(&b, "");
    WByte(&b, 0);
    WU32(&b, 0);
    if (b.err) {
        return -1;
    }
    RtFree(c->serverKexInit);
    c->serverKexInit = RtAlloc(b.len);
    if (c->serverKexInit == NULL) {
        return -1;
    }
    memcpy(c->serverKexInit, b.p, b.len);
    c->serverKexInitLen = b.len;
    c->kexInitSent = TRUE;
    return SendPacket(c, b.p, b.len);
}

static int Negotiate(SSH_CONN *c)
{
    RBUF         r;
    const UINT8 *kex, *hk, *encCs, *encSc, *macCs, *macSc, *compCs, *compSc, *lang;
    UINTN        kexL, hkL, encCsL, encScL, macCsL, macScL, compCsL, compScL, langL;
    const UINT8 *pick;
    UINTN        pickL;
    UINT8        firstFollows;

    if (c->clientKexInitLen < 17) {
        Disconnect(c, DISC_PROTOCOL_ERROR, "short KEXINIT");
        return -1;
    }
    RInit(&r, c->clientKexInit + 17, c->clientKexInitLen - 17);
    RStr(&r, &kex, &kexL);
    RStr(&r, &hk, &hkL);
    RStr(&r, &encCs, &encCsL);
    RStr(&r, &encSc, &encScL);
    RStr(&r, &macCs, &macCsL);
    RStr(&r, &macSc, &macScL);
    RStr(&r, &compCs, &compCsL);
    RStr(&r, &compSc, &compScL);
    RStr(&r, &lang, &langL);
    RStr(&r, &lang, &langL);
    firstFollows = RByte(&r);
    RU32(&r);
    if (r.err) {
        Disconnect(c, DISC_PROTOCOL_ERROR, "bad KEXINIT");
        return -1;
    }

    pick = PickAlg(kex, kexL, KEX_ALGS, &pickL);
    if (pick == NULL) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "no common kex algorithm (need curve25519-sha256)");
        return -1;
    }
    c->ignoreNextKexPacket = FALSE;
    if (firstFollows) {
        if (FirstEntryLen(kex, kexL) != pickL || memcmp(kex, pick, pickL) != 0 || !NameIs(hk, FirstEntryLen(hk, hkL), "ssh-ed25519")) {
            c->ignoreNextKexPacket = TRUE;
        }
    }
    if (PickAlg(hk, hkL, HOSTKEY_ALGS, &pickL) == NULL) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "no common host key algorithm (need ssh-ed25519)");
        return -1;
    }
    pick = PickAlg(encCs, encCsL, ENC_ALGS, &pickL);
    if (pick == NULL) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "no common cipher (need aes-ctr)");
        return -1;
    }
    c->nextEncKeyLenIn = EncKeyLen(pick, pickL);
    pick = PickAlg(encSc, encScL, ENC_ALGS, &pickL);
    if (pick == NULL) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "no common cipher (need aes-ctr)");
        return -1;
    }
    c->nextEncKeyLenOut = EncKeyLen(pick, pickL);
    pick = PickAlg(macCs, macCsL, MAC_ALGS, &pickL);
    if (pick == NULL) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "no common MAC (need hmac-sha2-256)");
        return -1;
    }
    c->nextMacTypeIn = MacType(pick, pickL);
    pick = PickAlg(macSc, macScL, MAC_ALGS, &pickL);
    if (pick == NULL) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "no common MAC (need hmac-sha2-256)");
        return -1;
    }
    c->nextMacTypeOut = MacType(pick, pickL);
    if (PickAlg(compCs, compCsL, COMP_ALGS, &pickL) == NULL || PickAlg(compSc, compScL, COMP_ALGS, &pickL) == NULL) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "compression not supported");
        return -1;
    }
    return 0;
}

static void HashStr(wc_Sha256 *sha, const void *d, UINTN n)
{
    UINT8 t[4];
    PutU32(t, (UINT32)n);
    wc_Sha256Update(sha, t, 4);
    wc_Sha256Update(sha, (const byte *)d, (word32)n);
}

static void DeriveKey(SSH_CONN *c, const UINT8 *kMp, UINTN kMpLen, const UINT8 *h, char letter, UINT8 *out, UINTN need)
{
    UINT8     tmp[96];
    UINTN     have;
    wc_Sha256 sha;

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, kMp, (word32)kMpLen);
    wc_Sha256Update(&sha, h, 32);
    wc_Sha256Update(&sha, (const byte *)&letter, 1);
    wc_Sha256Update(&sha, c->sessionId, 32);
    wc_Sha256Final(&sha, tmp);
    have = 32;
    while (have < need) {
        wc_InitSha256(&sha);
        wc_Sha256Update(&sha, kMp, (word32)kMpLen);
        wc_Sha256Update(&sha, h, 32);
        wc_Sha256Update(&sha, tmp, (word32)have);
        wc_Sha256Final(&sha, tmp + have);
        have += 32;
    }
    wc_Sha256Free(&sha);
    memcpy(out, tmp, need);
    memset(tmp, 0, sizeof(tmp));
}

static int DoKexDh(SSH_CONN *c, const UINT8 *payload, UINTN len)
{
    RBUF           r;
    const UINT8   *qc;
    UINTN          qcLen;
    curve25519_key mine, theirs;
    UINT8          qs[32], k[32], h[32], sig[64];
    word32         qsLen = 32, kLen = 32, sigLen = 64;
    UINT8          kMp[4 + 33];
    UINT8          ks[4 + 11 + 4 + 32];
    UINT8          ivCs[16], ivSc[16], keyCs[32], keySc[32], macCs[64], macSc[64];
    WBUF           b;
    wc_Sha256      sha;
    int            ret;

    RInit(&r, payload + 1, len - 1);
    RStr(&r, &qc, &qcLen);
    if (r.err || qcLen != 32) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "bad KEXDH_INIT");
        return -1;
    }

    wc_curve25519_init(&mine);
    wc_curve25519_init(&theirs);
    ret = wc_curve25519_make_key(&c->rng, 32, &mine);
    if (ret == 0) {
        ret = wc_curve25519_export_public_ex(&mine, qs, &qsLen, EC25519_LITTLE_ENDIAN);
    }
    if (ret == 0) {
        ret = wc_curve25519_import_public_ex(qc, 32, &theirs, EC25519_LITTLE_ENDIAN);
    }
    if (ret == 0) {
        ret = wc_curve25519_shared_secret_ex(&mine, &theirs, k, &kLen, EC25519_LITTLE_ENDIAN);
    }
    wc_curve25519_free(&mine);
    wc_curve25519_free(&theirs);
    if (ret != 0 || kLen != 32) {
        Print("SSH: curve25519 failed (%d)\n", ret);
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "curve25519 failure");
        return -1;
    }

    /* K as an mpint including its length prefix, the form the hash and key derivation use. */
    WInit(&b, kMp, sizeof(kMp));
    WMpint(&b, k, 32);
    memset(k, 0, sizeof(k));
    if (b.err) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "mpint");
        return -1;
    }

    /* Host key blob K_S */
    {
        WBUF kb;
        WInit(&kb, ks, sizeof(ks));
        WCStr(&kb, "ssh-ed25519");
        WStr(&kb, c->hostPub, 32);
    }

    /* Exchange hash H */
    wc_InitSha256(&sha);
    HashStr(&sha, c->clientVersion, c->clientVersionLen);
    HashStr(&sha, SSH_SERVER_VERSION, strlen(SSH_SERVER_VERSION));
    HashStr(&sha, c->clientKexInit, c->clientKexInitLen);
    HashStr(&sha, c->serverKexInit, c->serverKexInitLen);
    HashStr(&sha, ks, sizeof(ks));
    HashStr(&sha, qc, 32);
    HashStr(&sha, qs, 32);
    wc_Sha256Update(&sha, kMp, (word32)b.len);
    wc_Sha256Final(&sha, h);
    wc_Sha256Free(&sha);
    if (!c->haveSessionId) {
        memcpy(c->sessionId, h, 32);
        c->haveSessionId = TRUE;
    }

    ret = wc_ed25519_sign_msg(h, 32, sig, &sigLen, &c->hostKey);
    if (ret != 0 || sigLen != 64) {
        Print("SSH: ed25519 sign failed (%d)\n", ret);
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "signature failure");
        return -1;
    }

    /* Derive all six keys before anything switches. */
    DeriveKey(c, kMp, b.len, h, 'A', ivCs, 16);
    DeriveKey(c, kMp, b.len, h, 'B', ivSc, 16);
    DeriveKey(c, kMp, b.len, h, 'C', keyCs, 32);
    DeriveKey(c, kMp, b.len, h, 'D', keySc, 32);
    DeriveKey(c, kMp, b.len, h, 'E', macCs, 64);
    DeriveKey(c, kMp, b.len, h, 'F', macSc, 64);
    memset(kMp, 0, sizeof(kMp));

    /* KEXDH_REPLY */
    {
        WBUF rb;
        WInit(&rb, c->pl, SSH_PL_BUF);
        WByte(&rb, MSG_KEXDH_REPLY);
        WStr(&rb, ks, sizeof(ks));
        WStr(&rb, qs, 32);
        WU32(&rb, 4 + 11 + 4 + 64);
        WCStr(&rb, "ssh-ed25519");
        WStr(&rb, sig, 64);
        if (rb.err || SendPacket(c, rb.p, rb.len) != 0) {
            return -1;
        }
        WInit(&rb, c->pl, SSH_PL_BUF);
        WByte(&rb, MSG_NEWKEYS);
        if (SendPacket(c, rb.p, rb.len) != 0) {
            return -1;
        }
    }

    /* Outgoing direction switches right after our NEWKEYS. */
    if (wc_AesSetKeyDirect(&c->out.aes, keySc, (word32)c->nextEncKeyLenOut, ivSc, AES_ENCRYPTION) != 0) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "aes key");
        return -1;
    }
    memcpy(c->out.macKey, macSc, 64);
    c->out.macType = c->nextMacTypeOut;
    c->out.macLen = MacLenOf(c->out.macType);
    c->out.macKeyLen = c->out.macLen;
    c->out.active = TRUE;

    /* Incoming direction waits for the client's NEWKEYS. */
    memcpy(c->pendKey, keyCs, 32);
    memcpy(c->pendIv, ivCs, 16);
    memcpy(c->pendMac, macCs, 64);
    c->pendKeyLen = c->nextEncKeyLenIn;
    c->pendMacType = c->nextMacTypeIn;

    memset(keyCs, 0, sizeof(keyCs));
    memset(keySc, 0, sizeof(keySc));
    memset(macCs, 0, sizeof(macCs));
    memset(macSc, 0, sizeof(macSc));
    c->kex = KX_WAIT_NEWKEYS;
    return 0;
}

static int ApplyNewKeys(SSH_CONN *c)
{
    if (wc_AesSetKeyDirect(&c->in.aes, c->pendKey, (word32)c->pendKeyLen, c->pendIv, AES_ENCRYPTION) != 0) {
        Disconnect(c, DISC_KEY_EXCHANGE_FAILED, "aes key");
        return -1;
    }
    memcpy(c->in.macKey, c->pendMac, 64);
    c->in.macType = c->pendMacType;
    c->in.macLen = MacLenOf(c->in.macType);
    c->in.macKeyLen = c->in.macLen;
    c->in.active = TRUE;
    memset(c->pendKey, 0, sizeof(c->pendKey));
    memset(c->pendMac, 0, sizeof(c->pendMac));
    c->kex = KX_IDLE;
    if (c->state == ST_KEX) {
        c->state = ST_AUTH;
        Print("SSH: key exchange done\n");
    }
    return 0;
}

/* Auth */

static int SendAuthFailure(SSH_CONN *c)
{
    WBUF b;
    WInit(&b, c->pl, SSH_PL_BUF);
    WByte(&b, MSG_USERAUTH_FAILURE);
    WCStr(&b, "password");
    WByte(&b, 0);
    return SendPacket(c, b.p, b.len);
}

static int HandleUserauth(SSH_CONN *c, const UINT8 *p, UINTN len)
{
    RBUF         r;
    const UINT8 *user, *service, *method, *pass;
    UINTN        userL, serviceL, methodL, passL;
    char         pw[256];
    BOOLEAN      ok;

    RInit(&r, p + 1, len - 1);
    RStr(&r, &user, &userL);
    RStr(&r, &service, &serviceL);
    RStr(&r, &method, &methodL);
    if (r.err) {
        Disconnect(c, DISC_PROTOCOL_ERROR, "bad USERAUTH_REQUEST");
        return -1;
    }
    if (!NameIs(service, serviceL, "ssh-connection")) {
        Disconnect(c, DISC_PROTOCOL_ERROR, "unknown service");
        return -1;
    }
    if (userL >= sizeof(c->user)) {
        userL = sizeof(c->user) - 1;
    }
    memcpy(c->user, user, userL);
    c->user[userL] = 0;

    if (!NameIs(method, methodL, "password")) {
        return SendAuthFailure(c);
    }
    if (RByte(&r) != 0) {
        return SendAuthFailure(c);
    }
    RStr(&r, &pass, &passL);
    if (r.err || passL >= sizeof(pw)) {
        return SendAuthFailure(c);
    }
    memcpy(pw, pass, passL);
    pw[passL] = 0;
    ok = c->auth(c->authCtx, c->user, pw);
    memset(pw, 0, sizeof(pw));
    if (ok) {
        WBUF b;
        WInit(&b, c->pl, SSH_PL_BUF);
        WByte(&b, MSG_USERAUTH_SUCCESS);
        c->authenticated = TRUE;
        c->state = ST_CONN;
        Print("SSH: user %s authenticated\n", c->user);
        return SendPacket(c, b.p, b.len);
    }
    c->authTries++;
    Print("SSH: password rejected for %s (%d/%d)\n", c->user, c->authTries, SSH_MAX_AUTH_TRIES);
    if (c->authTries >= SSH_MAX_AUTH_TRIES) {
        Disconnect(c, DISC_NO_MORE_AUTH_METHODS, "too many failed attempts");
        return -1;
    }
    return SendAuthFailure(c);
}

/* Connection layer */

static void RingPush(SSH_CONN *c, const UINT8 *d, UINTN n)
{
    UINTN i;
    for (i = 0; i < n; i++) {
        UINTN next = (c->inHead + 1) % SSH_IN_RING;
        if (next == c->inTail) {
            return;
        }
        c->inRing[c->inHead] = d[i];
        c->inHead = next;
    }
}

static BOOLEAN RingEmpty(SSH_CONN *c)
{
    return (BOOLEAN)(c->inHead == c->inTail);
}

static int SendChannelReply(SSH_CONN *c, UINT8 msg)
{
    WBUF b;
    WInit(&b, c->pl, SSH_PL_BUF);
    WByte(&b, msg);
    WU32(&b, c->remoteChan);
    return SendPacket(c, b.p, b.len);
}

static int HandleChannelOpen(SSH_CONN *c, const UINT8 *p, UINTN len)
{
    RBUF         r;
    const UINT8 *type;
    UINTN        typeL;
    UINT32       sender, window, maxPkt;
    WBUF         b;

    RInit(&r, p + 1, len - 1);
    RStr(&r, &type, &typeL);
    sender = RU32(&r);
    window = RU32(&r);
    maxPkt = RU32(&r);
    if (r.err) {
        Disconnect(c, DISC_PROTOCOL_ERROR, "bad CHANNEL_OPEN");
        return -1;
    }
    WInit(&b, c->pl, SSH_PL_BUF);
    if (NameIs(type, typeL, "session") && !c->chanOpen) {
        c->chanOpen = TRUE;
        c->remoteChan = sender;
        c->remoteWindow = window;
        c->remoteMaxPkt = maxPkt;
        c->closeSent = FALSE;
        c->closeRecv = FALSE;
        c->remoteEof = FALSE;
        WByte(&b, MSG_CHANNEL_OPEN_CONFIRM);
        WU32(&b, sender);
        WU32(&b, 0);
        WU32(&b, SSH_LOCAL_WINDOW);
        WU32(&b, SSH_LOCAL_MAXPKT);
    } else {
        WByte(&b, MSG_CHANNEL_OPEN_FAILURE);
        WU32(&b, sender);
        WU32(&b, c->chanOpen ? 4 : 3);
        WCStr(&b, c->chanOpen ? "only one session per connection" : "unsupported channel type");
        WCStr(&b, "");
    }
    return SendPacket(c, b.p, b.len);
}

static int HandleChannelRequest(SSH_CONN *c, const UINT8 *p, UINTN len)
{
    RBUF         r;
    const UINT8 *type;
    UINTN        typeL;
    UINT32       recipient;
    UINT8        wantReply;
    BOOLEAN      ok = FALSE;

    RInit(&r, p + 1, len - 1);
    recipient = RU32(&r);
    RStr(&r, &type, &typeL);
    wantReply = RByte(&r);
    if (r.err || recipient != 0 || !c->chanOpen) {
        Disconnect(c, DISC_PROTOCOL_ERROR, "bad CHANNEL_REQUEST");
        return -1;
    }
    if (NameIs(type, typeL, "pty-req")) {
        const UINT8 *term;
        UINTN termL;
        UINT32 cols, rows;
        RStr(&r, &term, &termL);
        cols = RU32(&r);
        rows = RU32(&r);
        if (!r.err) {
            if (cols > 0 && cols < 1000) {
                c->cols = cols;
            }
            if (rows > 0 && rows < 1000) {
                c->rows = rows;
            }
            ok = TRUE;
        }
    } else if (NameIs(type, typeL, "shell")) {
        c->shellReady = TRUE;
        ok = TRUE;
    } else if (NameIs(type, typeL, "window-change")) {
        UINT32 cols = RU32(&r);
        UINT32 rows = RU32(&r);
        if (!r.err) {
            if (cols > 0 && cols < 1000) {
                c->cols = cols;
            }
            if (rows > 0 && rows < 1000) {
                c->rows = rows;
            }
        }
        ok = TRUE;
    } else if (NameIs(type, typeL, "env")) {
        ok = TRUE;
    }
    if (wantReply) {
        return SendChannelReply(c, ok ? MSG_CHANNEL_SUCCESS : MSG_CHANNEL_FAILURE);
    }
    return 0;
}

static int HandlePacket(SSH_CONN *c, const UINT8 *p, UINTN len)
{
    UINT8 msg;
    RBUF  r;

    if (len == 0) {
        Disconnect(c, DISC_PROTOCOL_ERROR, "empty payload");
        return -1;
    }
    msg = p[0];
    if (c->ignoreNextKexPacket && msg >= 30 && msg <= 49) {
        c->ignoreNextKexPacket = FALSE;
        return 0;
    }
    if (c->state == ST_VERSION) {
        Disconnect(c, DISC_PROTOCOL_ERROR, "packet before version");
        return -1;
    }

    switch (msg) {
    case MSG_DISCONNECT:
        Print("SSH: client disconnected\n");
        c->state = ST_CLOSED;
        return -1;

    case MSG_IGNORE:
    case MSG_DEBUG:
    case MSG_UNIMPLEMENTED:
    case MSG_EXT_INFO:
        return 0;

    case MSG_KEXINIT:
        if (c->kex != KX_IDLE && c->kex != KX_WAIT_KEXINIT) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "unexpected KEXINIT");
            return -1;
        }
        RtFree(c->clientKexInit);
        c->clientKexInit = RtAlloc(len);
        if (c->clientKexInit == NULL) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "out of memory");
            return -1;
        }
        memcpy(c->clientKexInit, p, len);
        c->clientKexInitLen = len;
        if (!c->kexInitSent && SendKexInit(c) != 0) {
            return -1;
        }
        c->kexInitSent = FALSE;
        if (Negotiate(c) != 0) {
            return -1;
        }
        c->kex = KX_WAIT_DH;
        return 0;

    case MSG_KEXDH_INIT:
        if (c->kex != KX_WAIT_DH) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "unexpected KEXDH_INIT");
            return -1;
        }
        return DoKexDh(c, p, len);

    case MSG_NEWKEYS:
        if (c->kex != KX_WAIT_NEWKEYS) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "unexpected NEWKEYS");
            return -1;
        }
        return ApplyNewKeys(c);

    case MSG_SERVICE_REQUEST: {
        const UINT8 *name;
        UINTN nameL;
        WBUF b;
        if (c->state < ST_AUTH) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "service request before kex");
            return -1;
        }
        RInit(&r, p + 1, len - 1);
        RStr(&r, &name, &nameL);
        if (r.err || !NameIs(name, nameL, "ssh-userauth")) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "unknown service");
            return -1;
        }
        WInit(&b, c->pl, SSH_PL_BUF);
        WByte(&b, MSG_SERVICE_ACCEPT);
        WCStr(&b, "ssh-userauth");
        return SendPacket(c, b.p, b.len);
    }

    case MSG_USERAUTH_REQUEST:
        if (c->state == ST_CONN) {
            return 0;
        }
        if (c->state != ST_AUTH) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "auth before kex");
            return -1;
        }
        return HandleUserauth(c, p, len);

    case MSG_GLOBAL_REQUEST: {
        const UINT8 *name;
        UINTN nameL;
        UINT8 wantReply;
        RInit(&r, p + 1, len - 1);
        RStr(&r, &name, &nameL);
        wantReply = RByte(&r);
        if (!r.err && wantReply) {
            WBUF b;
            WInit(&b, c->pl, SSH_PL_BUF);
            WByte(&b, MSG_REQUEST_FAILURE);
            return SendPacket(c, b.p, b.len);
        }
        return 0;
    }

    case MSG_CHANNEL_OPEN:
        if (c->state != ST_CONN) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "channel before auth");
            return -1;
        }
        return HandleChannelOpen(c, p, len);

    case MSG_CHANNEL_REQUEST:
        if (c->state != ST_CONN) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "channel before auth");
            return -1;
        }
        return HandleChannelRequest(c, p, len);

    case MSG_CHANNEL_DATA: {
        const UINT8 *d;
        UINTN dL;
        RInit(&r, p + 1, len - 1);
        if (RU32(&r) != 0 || !c->chanOpen) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "bad channel");
            return -1;
        }
        RStr(&r, &d, &dL);
        if (r.err) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "bad CHANNEL_DATA");
            return -1;
        }
        RingPush(c, d, dL);
        return 0;
    }

    case MSG_CHANNEL_EXTENDED_DATA:
        return 0;

    case MSG_CHANNEL_WINDOW_ADJUST: {
        UINT32 add;
        RInit(&r, p + 1, len - 1);
        RU32(&r);
        add = RU32(&r);
        if (!r.err) {
            c->remoteWindow += add;
        }
        return 0;
    }

    case MSG_CHANNEL_EOF:
        c->remoteEof = TRUE;
        return 0;

    case MSG_CHANNEL_CLOSE:
        c->closeRecv = TRUE;
        if (c->chanOpen && !c->closeSent) {
            c->closeSent = TRUE;
            SendChannelReply(c, MSG_CHANNEL_CLOSE);
        }
        return 0;

    default: {
        WBUF b;
        WInit(&b, c->pl, SSH_PL_BUF);
        WByte(&b, MSG_UNIMPLEMENTED);
        WU32(&b, c->in.seq - 1);
        return SendPacket(c, b.p, b.len);
    }
    }
}

/* Input assembly. Returns 1 when a packet was processed, 0 when more bytes are needed, -1 when the connection closed. */
static int TryProcessOne(SSH_CONN *c)
{
    UINTN  first;
    UINTN  total;
    UINTN  need;
    UINT8  padLen;
    UINTN  payloadLen;
    int    ret;

    if (c->state == ST_CLOSED) {
        return -1;
    }

    if (c->state == ST_VERSION) {
        UINTN i;
        for (i = 0; i < c->rxLen; i++) {
            if (c->rx[i] == '\n') {
                break;
            }
        }
        if (i == c->rxLen) {
            if (c->rxLen >= 255) {
                Disconnect(c, DISC_PROTOCOL_ERROR, "version line too long");
                return -1;
            }
            return 0;
        }
        {
            UINTN lineLen = i;
            if (lineLen > 0 && c->rx[lineLen - 1] == '\r') {
                lineLen--;
            }
            if (lineLen >= 4 && memcmp(c->rx, "SSH-", 4) == 0) {
                if (lineLen < 8 || (memcmp(c->rx, "SSH-2.0", 7) != 0 && memcmp(c->rx, "SSH-1.99", 8) != 0)) {
                    Disconnect(c, DISC_PROTOCOL_ERROR, "only SSH 2.0 is supported");
                    return -1;
                }
                memcpy(c->clientVersion, c->rx, lineLen);
                c->clientVersionLen = lineLen;
                c->clientVersion[lineLen] = 0;
                Print("SSH: client %s\n", c->clientVersion);
                c->state = ST_KEX;
                c->kex = KX_WAIT_KEXINIT;
            }
            memmove(c->rx, c->rx + i + 1, c->rxLen - i - 1);
            c->rxLen -= i + 1;
            if (c->state == ST_KEX && !c->kexInitSent && SendKexInit(c) != 0) {
                return -1;
            }
            return 1;
        }
    }

    first = c->in.active ? 16 : 4;
    if (!c->rxHaveLen) {
        UINTN blk = c->in.active ? 16 : 8;
        if (c->rxLen < first) {
            return 0;
        }
        if (c->in.active && wc_AesCtrEncrypt(&c->in.aes, c->rx, c->rx, 16) != 0) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "decrypt");
            return -1;
        }
        c->rxPktLen = GetU32(c->rx);
        if (c->rxPktLen < 5 || c->rxPktLen > SSH_MAX_PACKET - 4 || ((4 + c->rxPktLen) % blk) != 0) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "bad packet length");
            return -1;
        }
        c->rxHaveLen = TRUE;
    }
    total = 4 + c->rxPktLen;
    need = total + (c->in.active ? (UINTN)c->in.macLen : 0);
    if (c->rxLen < need) {
        return 0;
    }

    if (c->in.active) {
        Hmac  h;
        UINT8 seqBe[4];
        UINT8 mac[64];
        UINT8 diff = 0;
        int   i;
        if (total > 16 && wc_AesCtrEncrypt(&c->in.aes, c->rx + 16, c->rx + 16, (word32)(total - 16)) != 0) {
            Disconnect(c, DISC_PROTOCOL_ERROR, "decrypt");
            return -1;
        }
        PutU32(seqBe, c->in.seq);
        if (wc_HmacInit(&h, NULL, INVALID_DEVID) != 0 ||
            wc_HmacSetKey(&h, c->in.macType, c->in.macKey, (word32)c->in.macKeyLen) != 0 ||
            wc_HmacUpdate(&h, seqBe, 4) != 0 ||
            wc_HmacUpdate(&h, c->rx, (word32)total) != 0 ||
            wc_HmacFinal(&h, mac) != 0) {
            wc_HmacFree(&h);
            Disconnect(c, DISC_MAC_ERROR, "mac");
            return -1;
        }
        wc_HmacFree(&h);
        for (i = 0; i < c->in.macLen; i++) {
            diff |= (UINT8)(mac[i] ^ c->rx[total + i]);
        }
        if (diff != 0) {
            Disconnect(c, DISC_MAC_ERROR, "MAC mismatch");
            return -1;
        }
    }

    padLen = c->rx[4];
    if (padLen < 4 || (UINTN)padLen + 1 > c->rxPktLen) {
        Disconnect(c, DISC_PROTOCOL_ERROR, "bad padding");
        return -1;
    }
    payloadLen = c->rxPktLen - 1 - padLen;
    c->in.seq++;
    if (gDebug) {
        Print("SSH: rx msg %u len %u\n", c->rx[5], (unsigned)payloadLen);
    }
    ret = HandlePacket(c, c->rx + 5, payloadLen);

    memmove(c->rx, c->rx + need, c->rxLen - need);
    c->rxLen -= need;
    c->rxHaveLen = FALSE;
    if (ret < 0 || c->state == ST_CLOSED) {
        return -1;
    }
    return 1;
}

/* Reads whatever the transport has and processes complete packets. progressed tells the caller whether anything happened. */
static int ProcessInput(SSH_CONN *c, BOOLEAN *progressed)
{
    *progressed = FALSE;
    for (;;) {
        BOOLEAN any = FALSE;
        int     n;
        if (c->state == ST_CLOSED) {
            return -1;
        }
        if (c->rxLen < SSH_RX_BUF) {
            n = c->rd(c->ioCtx, c->rx + c->rxLen, SSH_RX_BUF - c->rxLen);
            if (n < 0) {
                if (c->state != ST_CLOSED && !c->closeSent) {
                    Print("SSH: connection lost\n");
                }
                c->state = ST_CLOSED;
                return -1;
            }
            if (n > 0) {
                c->rxLen += (UINTN)n;
                any = TRUE;
            }
        }
        for (;;) {
            int r = TryProcessOne(c);
            if (r < 0) {
                return -1;
            }
            if (r == 0) {
                break;
            }
            any = TRUE;
        }
        if (!any) {
            return 0;
        }
        *progressed = TRUE;
    }
}

/* Public API */

static int LoadHostKey(ed25519_key *key, UINT8 *pub, const UINT8 *seed)
{
    int ret = wc_ed25519_init(key);
    if (ret == 0) {
        ret = wc_ed25519_import_private_only(seed, 32, key);
    }
    if (ret == 0) {
        ret = wc_ed25519_make_public(key, pub, 32);
    }
    if (ret == 0) {
        ret = wc_ed25519_import_private_key(seed, 32, pub, 32, key);
    }
    return ret;
}

SSH_CONN *SshNew(SSH_IO_READ rd, SSH_IO_WRITE wr, void *ioCtx, const UINT8 *hostSeed32, SSH_AUTH_FN auth, void *authCtx)
{
    SSH_CONN *c = RtAllocZero(sizeof(SSH_CONN));
    int ret;

    if (c == NULL) {
        return NULL;
    }
    c->rd = rd;
    c->wr = wr;
    c->ioCtx = ioCtx;
    c->auth = auth;
    c->authCtx = authCtx;
    c->state = ST_VERSION;
    c->kex = KX_IDLE;
    c->cols = 80;
    c->rows = 25;

    c->rx = RtAlloc(SSH_RX_BUF);
    c->tx = RtAlloc(SSH_TX_BUF);
    c->pl = RtAlloc(SSH_PL_BUF);
    c->inRing = RtAlloc(SSH_IN_RING);
    if (c->rx == NULL || c->tx == NULL || c->pl == NULL || c->inRing == NULL) {
        Print("SSH: out of memory\n");
        SshFree(c);
        return NULL;
    }
    if (gDebug) {
        Print("SSH: init RNG (health test runs first, then seeding)\n");
    }
    ret = wc_InitRng(&c->rng);
    if (ret != 0) {
        Print("SSH: RNG init failed (%d). No entropy source?\n", ret);
        SshFree(c);
        return NULL;
    }
    c->rngInit = TRUE;
    ret = LoadHostKey(&c->hostKey, c->hostPub, hostSeed32);
    if (ret != 0) {
        Print("SSH: host key load failed (%d)\n", ret);
        SshFree(c);
        return NULL;
    }
    c->hostKeyInit = TRUE;
    if (gDebug) {
        Print("SSH: RNG and host key ready\n");
    }
    if (wc_AesInit(&c->in.aes, NULL, INVALID_DEVID) != 0 || wc_AesInit(&c->out.aes, NULL, INVALID_DEVID) != 0) {
        SshFree(c);
        return NULL;
    }
    return c;
}

void SshFree(SSH_CONN *c)
{
    if (c == NULL) {
        return;
    }
    if (c->hostKeyInit) {
        wc_ed25519_free(&c->hostKey);
    }
    if (c->rngInit) {
        wc_FreeRng(&c->rng);
    }
    wc_AesFree(&c->in.aes);
    wc_AesFree(&c->out.aes);
    RtFree(c->clientKexInit);
    RtFree(c->serverKexInit);
    RtFree(c->rx);
    RtFree(c->tx);
    RtFree(c->pl);
    RtFree(c->inRing);
    memset(c, 0, sizeof(*c));
    RtFree(c);
}

int SshPoll(SSH_CONN *c)
{
    BOOLEAN prog;
    return ProcessInput(c, &prog);
}

int SshAccept(SSH_CONN *c)
{
    UINTN  idle = 0;
    UINT64 start = RtNow();

    if (!c->versionSent) {
        char line[80];
        UINTN n = strlen(SSH_SERVER_VERSION);
        memcpy(line, SSH_SERVER_VERSION, n);
        line[n++] = '\r';
        line[n++] = '\n';
        if (gDebug) {
            Print("SSH: sending version\n");
        }
        if (c->wr(c->ioCtx, (const UINT8 *)line, n) != 0) {
            c->state = ST_CLOSED;
            return -1;
        }
        c->versionSent = TRUE;
        if (gDebug) {
            Print("SSH: version sent, waiting for the client\n");
        }
    }
    while (c->state != ST_CLOSED) {
        BOOLEAN prog;
        if (ProcessInput(c, &prog) < 0) {
            return -1;
        }
        if (c->shellReady) {
            Print("SSH: shell requested, terminal %ux%u\n", c->cols, c->rows);
            return 0;
        }
        if (prog) {
            idle = 0;
            start = RtNow();
        } else {
            gBS->Stall(1000);
            idle++;
            if (RtTimedOut(start, idle, 1000, SSH_ACCEPT_TIMEOUT_MS)) {
                Disconnect(c, DISC_BY_APPLICATION, "handshake timeout");
                return -1;
            }
        }
    }
    return -1;
}

int SshRead(SSH_CONN *c, UINT8 *buf, UINTN max)
{
    BOOLEAN prog;
    UINTN   n = 0;

    ProcessInput(c, &prog);
    if (RingEmpty(c)) {
        if (c->state == ST_CLOSED || c->closeRecv || c->remoteEof || !c->chanOpen) {
            return -1;
        }
        return 0;
    }
    while (n < max && !RingEmpty(c)) {
        buf[n++] = c->inRing[c->inTail];
        c->inTail = (c->inTail + 1) % SSH_IN_RING;
    }
    c->consumed += (UINT32)n;
    if (c->consumed >= SSH_LOCAL_WINDOW / 2 && CanSendNow(c)) {
        WBUF b;
        WInit(&b, c->pl, SSH_PL_BUF);
        WByte(&b, MSG_CHANNEL_WINDOW_ADJUST);
        WU32(&b, c->remoteChan);
        WU32(&b, c->consumed);
        if (SendPacket(c, b.p, b.len) == 0) {
            c->consumed = 0;
        }
    }
    return (int)n;
}

int SshWrite(SSH_CONN *c, const UINT8 *buf, UINTN len)
{
    while (len > 0) {
        UINTN  waited = 0;
        UINT64 start = RtNow();
        UINTN  chunk;
        WBUF   b;

        while (c->state == ST_CONN && c->chanOpen && !c->closeSent && !c->closeRecv && (!CanSendNow(c) || c->remoteWindow == 0)) {
            BOOLEAN prog;
            if (ProcessInput(c, &prog) < 0) {
                return -1;
            }
            if (!prog) {
                gBS->Stall(1000);
                waited++;
                if (RtTimedOut(start, waited, 1000, SSH_WRITE_TIMEOUT_MS)) {
                    return -1;
                }
            }
        }
        if (!CanSendNow(c) || c->closeRecv || c->remoteWindow == 0) {
            return -1;
        }
        chunk = len;
        if (chunk > c->remoteWindow) {
            chunk = c->remoteWindow;
        }
        if (chunk > c->remoteMaxPkt) {
            chunk = c->remoteMaxPkt;
        }
        if (chunk > SSH_DATA_CHUNK) {
            chunk = SSH_DATA_CHUNK;
        }
        WInit(&b, c->pl, SSH_PL_BUF);
        WByte(&b, MSG_CHANNEL_DATA);
        WU32(&b, c->remoteChan);
        WStr(&b, buf, chunk);
        if (b.err || SendPacket(c, b.p, b.len) != 0) {
            return -1;
        }
        c->remoteWindow -= (UINT32)chunk;
        buf += chunk;
        len -= chunk;
    }
    return 0;
}

void SshClose(SSH_CONN *c, UINT32 exitStatus)
{
    if (c == NULL) {
        return;
    }
    if (c->state == ST_CONN && c->chanOpen && !c->closeSent) {
        WBUF  b;
        UINTN waited = 0;
        WInit(&b, c->pl, SSH_PL_BUF);
        WByte(&b, MSG_CHANNEL_REQUEST);
        WU32(&b, c->remoteChan);
        WCStr(&b, "exit-status");
        WByte(&b, 0);
        WU32(&b, exitStatus);
        SendPacket(c, b.p, b.len);
        SendChannelReply(c, MSG_CHANNEL_EOF);
        SendChannelReply(c, MSG_CHANNEL_CLOSE);
        c->closeSent = TRUE;
        {
            UINT64 start = RtNow();
            while (c->state != ST_CLOSED && !c->closeRecv) {
                BOOLEAN prog;
                if (ProcessInput(c, &prog) < 0) {
                    break;
                }
                if (!prog) {
                    gBS->Stall(1000);
                    waited++;
                    if (RtTimedOut(start, waited, 1000, SSH_CLOSE_TIMEOUT_MS)) {
                        break;
                    }
                }
            }
        }
    }
    if (c->state != ST_CLOSED) {
        Disconnect(c, DISC_BY_APPLICATION, "session ended");
    }
}

BOOLEAN SshIsOpen(SSH_CONN *c)
{
    return (BOOLEAN)(c != NULL && c->state == ST_CONN && c->chanOpen && !c->closeRecv && !c->closeSent);
}

void SshGetWindow(SSH_CONN *c, UINT32 *cols, UINT32 *rows)
{
    *cols = c->cols;
    *rows = c->rows;
}

const char *SshUser(SSH_CONN *c)
{
    return c->user;
}

void SshPrintHostKey(const UINT8 *hostSeed32)
{
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ed25519_key key;
    UINT8       pub[32];
    UINT8       blob[4 + 11 + 4 + 32];
    UINT8       digest[32];
    char        out[48];
    WBUF        b;
    wc_Sha256   sha;
    int         i, o = 0;

    if (LoadHostKey(&key, pub, hostSeed32) != 0) {
        Print("Host key: invalid seed\n");
        return;
    }
    wc_ed25519_free(&key);
    WInit(&b, blob, sizeof(blob));
    WCStr(&b, "ssh-ed25519");
    WStr(&b, pub, 32);
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, blob, (word32)b.len);
    wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);
    for (i = 0; i < 30; i += 3) {
        UINT32 v = ((UINT32)digest[i] << 16) | ((UINT32)digest[i + 1] << 8) | digest[i + 2];
        out[o++] = b64[(v >> 18) & 63];
        out[o++] = b64[(v >> 12) & 63];
        out[o++] = b64[(v >> 6) & 63];
        out[o++] = b64[v & 63];
    }
    {
        UINT32 v = ((UINT32)digest[30] << 16) | ((UINT32)digest[31] << 8);
        out[o++] = b64[(v >> 18) & 63];
        out[o++] = b64[(v >> 12) & 63];
        out[o++] = b64[(v >> 6) & 63];
    }
    out[o] = 0;
    Print("Host key: ssh-ed25519 SHA256:%s\n", out);
}
