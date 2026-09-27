#include "jkpacket.h"

#include <stdlib.h>
#include <string.h>

/* JacKnife packet parser.
 *
 * This file is JacKnife's own target. The bugs below are intentional and
 * seeded so AddressSanitizer and UndefinedBehaviorSanitizer have something
 * real to report. They are not a general-purpose exploit toolkit.
 *
 *   JK-HEAP-001  BIND  copies a trusted-length payload into a 16-byte heap buffer
 *   JK-STACK-001 LABEL copies a trusted-length payload into an 8-byte stack buffer
 *   JK-UAF-001   DROP+READ frees the session buffer and then loads through it
 *   JK-UB-001    SCALE adds two int32 values with no overflow check
 */

enum {
    JK_OP_BIND = 0x01,
    JK_OP_LABEL = 0x03,
    JK_OP_DROP = 0x04,
    JK_OP_READ = 0x05,
    JK_OP_SCALE = 0x06
};

enum {
    JK_LIVE_EMPTY = 0,
    JK_LIVE_ALLOC = 1,
    JK_LIVE_DANGLING = 2
};

#define JK_BIND_CAP 16
#define JK_LABEL_CAP 8

typedef struct {
    uint8_t *buf;
    int live;
} session_t;

static int remaining(size_t size, size_t off, size_t need) {
    if (off > size) {
        return 0;
    }
    return (size - off) >= need;
}

__attribute__((noinline))
static void bug_heap_bind(session_t *session, const uint8_t *payload, size_t claimed) {
    if (session->live == JK_LIVE_ALLOC && session->buf != NULL) {
        free(session->buf);
        session->buf = NULL;
        session->live = JK_LIVE_EMPTY;
    }
    session->buf = (uint8_t *)malloc(JK_BIND_CAP);
    if (session->buf == NULL) {
        session->live = JK_LIVE_EMPTY;
        return;
    }
    session->live = JK_LIVE_ALLOC;
    /* JK-HEAP-001: claimed is bounded by the input size, not by JK_BIND_CAP. */
    memcpy(session->buf, payload, claimed);
}

__attribute__((noinline))
static void bug_stack_label(const uint8_t *payload, size_t claimed) {
    char label[JK_LABEL_CAP];
    /* JK-STACK-001: claimed is not bounded by JK_LABEL_CAP. */
    memcpy(label, payload, claimed);
    /* Keep the buffer live so the overflow is not deleted as a dead store. */
    volatile char sink = label[0];
    (void)sink;
}

__attribute__((noinline))
static void bug_scale_add(int32_t left, int32_t right) {
    /* JK-UB-001: signed overflow is undefined. UBSan is expected to abort. */
    volatile int32_t sink = left + right;
    (void)sink;
}

int jkpacket_parse(const uint8_t *data, size_t size) {
    session_t session;
    size_t off = 4;
    int frames;

    session.buf = NULL;
    session.live = JK_LIVE_EMPTY;

    if (data == NULL || size < 4) {
        return 0;
    }
    if (data[0] != 'J' || data[1] != 'K' || data[2] != 'P' || data[3] != 'K') {
        return 0;
    }

    for (frames = 0; frames < 16; frames++) {
        uint8_t opcode;
        uint8_t flags;
        size_t claimed;
        const uint8_t *payload;

        if (!remaining(size, off, 5)) {
            break;
        }
        opcode = data[off];
        flags = data[off + 1];
        claimed = (size_t)data[off + 3] | ((size_t)data[off + 4] << 8);
        off += 5;
        if (!remaining(size, off, claimed)) {
            break;
        }
        payload = data + off;

        switch (opcode) {
        case JK_OP_BIND:
            bug_heap_bind(&session, payload, claimed);
            break;
        case JK_OP_LABEL:
            bug_stack_label(payload, claimed);
            break;
        case JK_OP_DROP:
            if (session.live == JK_LIVE_ALLOC && session.buf != NULL) {
                free(session.buf);
                /* JK-UAF-001: pointer intentionally retained. */
                session.live = JK_LIVE_DANGLING;
            }
            break;
        case JK_OP_READ:
            if (session.live != JK_LIVE_EMPTY && session.buf != NULL) {
                volatile uint8_t sink = session.buf[0];
                (void)sink;
            }
            break;
        case JK_OP_SCALE:
            if (claimed >= 8) {
                int32_t left;
                int32_t right;
                memcpy(&left, payload, 4);
                memcpy(&right, payload + 4, 4);
                if ((flags & 0x01u) == 0) {
                    bug_scale_add(left, right);
                }
            }
            break;
        default:
            break;
        }
        (void)flags;
        off += claimed;
    }

    if (session.live == JK_LIVE_ALLOC && session.buf != NULL) {
        free(session.buf);
        session.buf = NULL;
        session.live = JK_LIVE_EMPTY;
    }
    return 0;
}
