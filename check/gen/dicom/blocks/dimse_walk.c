/* ---- DIMSE command set walker ---- */
/*
 * Copied verbatim into rules 201, 202 and 213 from check/gen/dicom/blocks/dimse_walk.c
 * by check/dicom-blocks.sh --write; make check fails when a copy differs. Edit that
 * file, not a copy. Requires mmt-dpi 1.9.0 or later: it reads tcp.payload_len bytes
 * of tcp.p_payload, which mmt-dpi bounds by the captured bytes since 1.9.0.
 *
 * Limits (evasion): only a P-DATA-TF whose PDU header starts the TCP segment and
 * whose first PDV is a whole command set inside the segment is judged. A stack that
 * writes the 12-byte PDU and PDV header in a segment of its own, as DCMTK does by
 * default, is not seen (mmt-dpi needs 10 bytes to extract dicom.pdu_type), nor is a
 * command set split across segments.
 */
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int cmd;            /* Command Field (0000,0100), -1 when absent */
    int has_msg_id;     /* Message ID (0000,0110) present */
    int status;         /* Status (0000,0900), -1 when absent */
} em_dimse_t;

static inline uint32_t em_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * Walk the command set of the first PDV of a P-DATA-TF at the start of payload
 * (implicit VR little endian, group 0000). Return 1 when it is a whole,
 * well-formed command set, 0 otherwise.
 */
static int em_dimse_walk(const void *payload, double payload_len, em_dimse_t *c) {
    const uint8_t *p = (const uint8_t *) payload;
    uint32_t n = (uint32_t) payload_len, pdv_len, end, off, len;

    c->cmd = -1;
    c->has_msg_id = 0;
    c->status = -1;
    /* PDU header (6) + PDV length (4) + context id (1) + message control header (1) */
    if (p == NULL || n < 12 || p[0] != 4 || p[11] != 0x03)
        return 0;
    pdv_len = ((uint32_t)p[6] << 24) | ((uint32_t)p[7] << 16) | ((uint32_t)p[8] << 8) | p[9];
    if (pdv_len < 2 || pdv_len > n - 10)
        return 0; /* the PDV is not wholly in this packet */
    end = 10 + pdv_len;

    /* group(2) element(2) length(4) value */
    for (off = 12; off + 8 <= end; off += 8 + len) {
        uint16_t group = p[off] | (p[off + 1] << 8);
        uint16_t elem  = p[off + 2] | (p[off + 3] << 8);
        len = em_le32(&p[off + 4]);
        if (group != 0 || len > end - off - 8)
            return 0;
        if (off == 12 && elem != 0x0000)
            return 0; /* a command set starts with Command Group Length */
        if (elem == 0x0100 && len == 2)
            c->cmd = p[off + 8] | (p[off + 9] << 8);
        else if (elem == 0x0110)
            c->has_msg_id = 1;
        else if (elem == 0x0900 && len == 2)
            c->status = p[off + 8] | (p[off + 9] << 8);
    }
    return off == end;
}
/* ---- end of DIMSE command set walker ---- */
