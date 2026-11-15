/*
 * eapol_parse.c — Standalone 802.11 EAPOL-Key (4-way handshake) parser.
 *
 * Pure parser: no daemon state, no sockets, no allocation — same contract as
 * beacon_parse.c so the unit tests can link it without the capture stack.
 * Decodes one RadioTap+802.11 data frame carrying an EAPOL-Key (EtherType
 * 0x888E) and reports everything `pwn4c harvest` needs to build a hashcat
 * 22000 line: message number, nonces, MIC, replay counter, and the PMKID KDE
 * some APs embed in message 1.
 *
 * Wire layout of the EAPOL-Key body (offsets from the EAPOL header start):
 *   [0] version  [1] type (3=Key)  [2..3] body length (BE)
 *   [4] descriptor (2=RSN, 254=WPA)  [5..6] key info (BE)
 *   [7..8] key length  [9..16] replay counter  [17..48] nonce
 *   [49..64] IV  [65..72] RSC  [73..80] key id  [81..96] MIC
 *   [97..98] key-data length (BE)  [99..] key data
 */

#include "pwn4cd.h"

#include <string.h>

/* ── Constants ────────────────────────────────────────────────────────────── */

#define EAPOL_TYPE_KEY       3u
#define EAPOL_DESC_RSN       2u
#define EAPOL_DESC_WPA       254u

/* Key Information bit masks (IEEE 802.11-2020, Figure 12-32). */
#define KEYINFO_PAIRWISE     0x0008u
#define KEYINFO_INSTALL      0x0040u
#define KEYINFO_ACK          0x0080u
#define KEYINFO_MIC          0x0100u
#define KEYINFO_SECURE       0x0200u
#define KEYINFO_ENCR_KEYDATA 0x1000u

#define EAPOL_KEY_FIXED_LEN  95u    /* body bytes after the 4-byte header  */
#define EAPOL_KEY_MIN_LEN    99u    /* header + fixed body                 */

#define LLC_SNAP_LEN         8u
#define RSN_KDE_OUI_LEN      4u     /* 00:0f:ac + type 04                  */
#define PMKID_LEN            16u

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* ── PMKID KDE ────────────────────────────────────────────────────────────── */

/*
 * kde_find_pmkid — Walk the unencrypted key data looking for the RSN PMKID
 * KDE: 0xdd, length, OUI 00:0f:ac, type 04, then 16 bytes of PMKID.
 */
static bool kde_find_pmkid(const uint8_t *data, size_t len, uint8_t out[16])
{
    size_t p = 0;

    while (p + 2u <= len) {
        uint8_t id   = data[p];
        uint8_t klen = data[p + 1];

        if (p + 2u + (size_t)klen > len) { break; }

        if (id == 0xddu && klen >= RSN_KDE_OUI_LEN + PMKID_LEN
            && data[p + 2] == 0x00 && data[p + 3] == 0x0f
            && data[p + 4] == 0xac && data[p + 5] == 0x04) {
            memcpy(out, data + p + 6, PMKID_LEN);
            return true;
        }

        p += 2u + (size_t)klen;
    }

    return false;
}

/* ── Frame parsing ────────────────────────────────────────────────────────── */

/*
 * eapol_parse_frame — Parse one RadioTap+802.11 frame into an EAPOL-Key
 * summary. Returns 0 when the frame is a pairwise 4-way message (or carries a
 * PMKID), -1 for anything else (beacons, ARP, group-key messages, fragments).
 */
int eapol_parse_frame(const uint8_t *frame, size_t len, eapol_msg_t *out)
{
    const uint8_t *eapol;
    size_t         rt;
    size_t         hdr;
    size_t         body;
    size_t         avail;
    uint16_t       body_len;
    uint16_t       key_info;
    uint8_t        fc0;
    uint8_t        fc1;
    uint8_t        subtype;
    bool           tods;
    bool           fromds;

    if (!frame || !out) { return -1; }
    memset(out, 0, sizeof(*out));

    if (len < 24u) { return -1; }

    rt = (size_t)frame[2] | ((size_t)frame[3] << 8);
    if (rt < 8u || rt + 24u > len) { return -1; }

    fc0 = frame[rt];
    fc1 = frame[rt + 1];

    /* Data frames only (type 2).  Management/control never carry EAPOL. */
    if (((fc0 >> 2) & 0x03u) != 0x02u) { return -1; }

    tods   = (fc1 & 0x01u) != 0;
    fromds = (fc1 & 0x02u) != 0;
    if (tods && fromds) { return -1; }   /* WDS: 4-address, not our case */

    /* QoS data subtypes carry the 2-byte QoS control field. */
    subtype = (uint8_t)((fc0 >> 4) & 0x0fu);
    hdr = 24u + (((subtype & 0x08u) != 0) ? 2u : 0u);

    if (tods) {
        memcpy(out->bssid, frame + rt + 4, 6);    /* Addr1 = BSSID */
        memcpy(out->sta,   frame + rt + 10, 6);   /* Addr2 = SA    */
    } else if (fromds) {
        memcpy(out->bssid, frame + rt + 10, 6);   /* Addr2 = BSSID */
        memcpy(out->sta,   frame + rt + 4, 6);    /* Addr1 = DA    */
    } else {
        return -1;                                /* IBSS: no BSSID */
    }

    body = rt + hdr;
    if (body + LLC_SNAP_LEN > len) { return -1; }

    /* LLC/SNAP: aa aa 03 00 00 00 88 8e */
    if (!(frame[body]     == 0xaau && frame[body + 1] == 0xaau
          && frame[body + 2] == 0x03u
          && frame[body + 3] == 0x00u && frame[body + 4] == 0x00u
          && frame[body + 5] == 0x00u
          && frame[body + 6] == 0x88u && frame[body + 7] == 0x8eu)) {
        return -1;
    }

    eapol = frame + body + LLC_SNAP_LEN;
    avail = len - body - LLC_SNAP_LEN;
    if (avail < EAPOL_KEY_MIN_LEN) { return -1; }

    if (eapol[1] != EAPOL_TYPE_KEY) { return -1; }
    if (eapol[4] != EAPOL_DESC_RSN && eapol[4] != EAPOL_DESC_WPA) {
        return -1;
    }

    body_len = be16(eapol + 2);
    if (body_len < EAPOL_KEY_FIXED_LEN) { return -1; }
    if ((size_t)body_len + 4u > avail) { return -1; }   /* truncated capture */

    key_info = be16(eapol + 5);

    /* Group-key messages (GTK rekey) are not crackable as a 4-way. */
    if ((key_info & KEYINFO_PAIRWISE) == 0) { return -1; }

    if (key_info & KEYINFO_ACK) {
        out->msg = (key_info & KEYINFO_MIC) ? 3u : 1u;
    } else if (key_info & KEYINFO_MIC) {
        out->msg = (key_info & KEYINFO_SECURE) ? 4u : 2u;
    } else {
        return -1;                       /* not part of the 4-way */
    }

    out->key_info = key_info;
    memcpy(out->replay, eapol + 9, 8);
    memcpy(out->nonce,  eapol + 17, 32);
    memcpy(out->mic,    eapol + 81, 16);

    /* Key data is only readable when it is not encrypted. */
    if ((key_info & KEYINFO_ENCR_KEYDATA) == 0) {
        uint16_t kd_len = be16(eapol + 97);

        if (kd_len >= RSN_KDE_OUI_LEN + PMKID_LEN
            && (size_t)EAPOL_KEY_MIN_LEN + (size_t)kd_len
                   <= (size_t)body_len + 4u) {
            out->has_pmkid = kde_find_pmkid(eapol + EAPOL_KEY_MIN_LEN,
                                            kd_len, out->pmkid);
        }
    }

    out->eapol     = eapol;
    out->eapol_len = (uint16_t)(body_len + 4u);
    return 0;
}
