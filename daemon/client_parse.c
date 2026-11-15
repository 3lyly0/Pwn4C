/*
 * client_parse.c — Standalone 802.11 station-observation parser.
 *
 * Pure parser: no daemon state, no sockets, no allocation — separated from
 * clients.c so the unit tests can link it without the capture stack. One
 * RadioTap+802.11 frame in, one station observation out:
 *
 *   probe request   -> station MAC + the SSID it is looking for (PNL entry)
 *   auth/assoc      -> station MAC + the BSSID it is joining
 *   data (ToDS)     -> station MAC + BSSID: it is associated and active
 *   deauth/disassoc -> station MAC + BSSID: the AP just kicked it
 *
 * Everything else (beacons, ACKs, control frames, WDS/IBSS data) is rejected.
 */

#include "pwn4cd.h"

#include <string.h>

static const uint8_t CL_ZERO_MAC[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static bool cl_is_group(const uint8_t mac[6])
{
    return (mac[0] & 0x01u) != 0;
}

/*
 * cl_parse_ies — Copy the SSID element out of an information-element list.
 * A probe request with an empty SSID is a wildcard probe: it is still a
 * useful observation (the station exists), just without a PNL entry.
 */
static void cl_parse_ies(const uint8_t *ies, size_t ies_len, client_frame_t *out)
{
    size_t p = 0;

    while (p + 2 <= ies_len) {
        uint8_t tag  = ies[p];
        uint8_t tlen = ies[p + 1];

        if (p + 2 + tlen > ies_len) { break; }

        if (tag == 0x00u) {
            size_t copy = tlen;
            if (copy > CL_SSID_MAX) { copy = CL_SSID_MAX; }
            memcpy(out->ssid, ies + p + 2, copy);
            out->ssid_len = (uint8_t)copy;
            out->has_ssid = true;
            return;
        }

        p += (size_t)2 + tlen;
    }
}

int client_parse_frame(const uint8_t *frame, size_t len, client_frame_t *out)
{
    rt_info_t      info;
    uint8_t        fc0;
    uint8_t        fc1;
    uint8_t        type;
    uint8_t        subtype;
    const uint8_t *addr1;
    const uint8_t *addr2;
    const uint8_t *addr3;
    size_t         ies_off;

    if (!frame || !out) { return -1; }
    memset(out, 0, sizeof(*out));

    if (scan_radiotap(frame, len, &info) < 0) { return -1; }
    if (info.rt_len + 24 > len) { return -1; }

    fc0     = frame[info.rt_len];
    fc1     = frame[info.rt_len + 1];
    type    = (uint8_t)((fc0 >> 2) & 0x03u);
    subtype = (uint8_t)((fc0 >> 4) & 0x0fu);

    addr1 = frame + info.rt_len + 4;
    addr2 = frame + info.rt_len + 10;
    addr3 = frame + info.rt_len + 16;

    out->signal_dbm = info.signal_dbm;
    out->has_signal = info.has_signal;

    ies_off = info.rt_len + 24;

    if (type == 0x00u) {                       /* management */
        switch (subtype) {
        case 0x04u:                            /* probe request */
            memcpy(out->sta, addr2, 6);
            if (!cl_is_group(addr3) && memcmp(addr3, CL_ZERO_MAC, 6) != 0) {
                memcpy(out->bssid, addr3, 6);
                out->has_bssid = true;
            }
            out->probe = true;
            /* No fixed parameters: the IEs start right after the header. */
            cl_parse_ies(frame + ies_off, len - ies_off, out);
            break;

        case 0x00u:                            /* association request */
        case 0x02u: {                          /* reassociation request */
            /* Fixed: capability + listen interval, plus the current AP for
             * reassociation. */
            size_t fixed = (subtype == 0x02u) ? 10u : 4u;

            memcpy(out->sta, addr2, 6);
            memcpy(out->bssid, addr3, 6);
            out->has_bssid = true;
            out->assoc     = true;
            if (ies_off + fixed <= len) {
                cl_parse_ies(frame + ies_off + fixed,
                             len - ies_off - fixed, out);
            }
            break;
        }

        case 0x0bu:                            /* authentication */
            memcpy(out->sta, addr2, 6);
            memcpy(out->bssid, addr3, 6);
            out->has_bssid = true;
            out->assoc     = true;
            break;

        case 0x0au:                            /* disassociation */
        case 0x0cu:                            /* deauthentication */
            /* Addr1 is the station being kicked, Addr2 the AP. */
            memcpy(out->sta, addr1, 6);
            memcpy(out->bssid, addr3, 6);
            out->has_bssid = true;
            out->left      = true;
            break;

        default:
            return -1;
        }
    } else if (type == 0x02u) {                /* data */
        bool to_ds   = (fc1 & 0x01u) != 0;
        bool from_ds = (fc1 & 0x02u) != 0;

        /* IBSS (neither) and WDS (both) have no unambiguous BSSID/STA pair. */
        if (to_ds == from_ds) { return -1; }

        if (to_ds) {
            memcpy(out->bssid, addr1, 6);      /* Addr1 = BSSID */
            memcpy(out->sta, addr2, 6);        /* Addr2 = SA    */
        } else {
            memcpy(out->sta, addr1, 6);        /* Addr1 = DA    */
            memcpy(out->bssid, addr2, 6);      /* Addr2 = BSSID */
        }
        out->has_bssid = true;
        out->data      = true;
    } else {
        return -1;                             /* control frames */
    }

    /* A station is a unicast, non-zero address; anything else is noise. */
    if (cl_is_group(out->sta) || memcmp(out->sta, CL_ZERO_MAC, 6) == 0) {
        return -1;
    }

    return 0;
}
