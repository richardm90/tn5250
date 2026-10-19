/* TN5250 - An implementation of the 5250 telnet protocol.
 * Copyright (C) 1997-2008 Michael Madore
 *
 * This file is part of TN5250.
 *
 * TN5250 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1, or (at your option)
 * any later version.
 *
 * TN5250 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307 USA
 *
 */
#include "tn5250-private.h"

/* External declarations of initializers for each type of stream. */
extern int tn5250_telnet_stream_init(Tn5250Stream* This);
#ifdef HAVE_LIBSSL
extern int tn5250_ssl_stream_init(Tn5250Stream* This);
#endif
#ifndef NDEBUG
extern int tn5250_debug_stream_init(Tn5250Stream* This);
#endif

/* This structure and the stream_types[] array defines what types of
 * streams we can create. */
struct _Tn5250StreamType {
    const char* prefix;
    int (*init)(Tn5250Stream* This);
};

typedef struct _Tn5250StreamType Tn5250StreamType;

static const Tn5250StreamType stream_types[] = {
    // clang-format off
    { "telnet:",     tn5250_telnet_stream_init },
    { "tn5250:",     tn5250_telnet_stream_init },
#ifdef HAVE_LIBSSL
    { "ssl:",        tn5250_ssl_stream_init    },
    { "telnet-ssl:", tn5250_ssl_stream_init    },
    { "telnets:",    tn5250_ssl_stream_init    },
#endif
#ifndef NDEBUG
    { "debug:",      tn5250_debug_stream_init  },
#endif
    { NULL,          NULL                      }
    // clang-format on
};

static void streamInit(Tn5250Stream* This, long timeout) {
    This->options = 0;
    This->status = 0;
    This->config = NULL;
    This->connect = NULL;
    This->disconnect = NULL;
    This->handle_receive = NULL;
    This->send_packet = NULL;
    This->destroy = NULL;
    This->record_count = 0;
    This->records = This->current_record = NULL;
    This->sockfd = (SOCKET_TYPE)-1;
    This->msec_wait = timeout;
    This->rcvbufpos = 0;
    This->rcvbuflen = -1;
    tn5250_buffer_init(&(This->sb_buf));
}

/****f* lib5250/tn5250_stream_open
 * NAME
 *    tn5250_stream_open
 * SYNOPSIS
 *    ret = tn5250_stream_open (to);
 * INPUTS
 *    const char *         to         - `URL' of host to connect to.
 *    Tn5250Config     *   config     - config to associate w/stream
 * DESCRIPTION
 *    Opens a 5250 stream to the specified host.  URL is of the format
 *    [protocol]:host:[port], where protocol is currently one of the following:
 *
 *       telnet - connect using tn5250 protocol
 *       tn5250 - connect using tn5250 protocol
 *       debug  - read recorded session from debug file
 *
 *    This is maintained by a protocol -> function mapping.  Each protocol has
 *    an associated function which is responsible for initializing the stream.
 *    Stream initialization sets up protocol specific functions to handle
 *    communication with the host system.
 *
 *    The next protocol to add is SNA.  This will allow the emulator to use
 *    APPC (LU 6.2) to establish a session with the AS/400.
 *****/
Tn5250Stream* tn5250_stream_open(const char* to, Tn5250Config* config) {
    Tn5250Stream* This = tn5250_new(Tn5250Stream, 1);
    const Tn5250StreamType* iter;
    const char* postfix;
    int ret;

#ifndef _WIN32
    /* A write to a socket the peer has already reset raises SIGPIPE, whose
     * default disposition -- with no handler installed, which is the case
     * in every consumer of this library -- terminates the whole process
     * immediately, before write()/SSL_write() even returns a value for
     * the error-handling this file and sslstream.c do (see their
     * This->failed writes) to have any chance to run. This is the same
     * category of problem exit(5) was -- a dropped connection killing the
     * process outright -- just via a signal instead of a direct call, and
     * unlike exit(5) it is not something any individual call site can
     * guard against on its own; it has to be suppressed process-wide,
     * once, before any socket I/O happens. SIGPIPE does not exist on
     * Windows. */
    signal(SIGPIPE, SIG_IGN);
#endif

    if (This != NULL) {

        streamInit(This, 0);

        if (config != NULL) {
            tn5250_stream_config(This, config);
        }

        /* Figure out the stream type. */
        iter = stream_types;
        while (iter->prefix != NULL) {
            if (strlen(to) >= strlen(iter->prefix) &&
                !memcmp(iter->prefix, to, strlen(iter->prefix))) {
                /* Found the stream type, initialize it. */
                ret = (*(iter->init))(This);
                if (ret != 0) {
                    tn5250_stream_destroy(This);
                    return NULL;
                }
                break;
            }
            iter++;
        }

        /* If we haven't found a type, assume telnet. */
        if (iter->prefix == NULL) {
            ret = tn5250_telnet_stream_init(This);
            if (ret != 0) {
                tn5250_stream_destroy(This);
                return NULL;
            }
            postfix = to;
        }
        else {
            postfix = to + strlen(iter->prefix);
        }

        /* Connect */
        ret = (*(This->connect))(This, postfix);
        if (ret == 0) {
            return This;
        }

        tn5250_stream_destroy(This);
    }
    return NULL;
}

/****f* lib5250/tn5250_stream_config
 * NAME
 *    tn5250_stream_config
 * SYNOPSIS
 *    tn5250_stream_config (This, config);
 * INPUTS
 *    Tn5250Stream *       This       - Stream object.
 *    Tn5250Config *       config     - Configuration object.
 * DESCRIPTION
 *    Associates a stream with a configuration object.  The stream uses the
 *    configuration object at run time to determine how to operate.
 *****/
int tn5250_stream_config(Tn5250Stream* This, Tn5250Config* config) {
    /* Always reference before unreferencing, in case it's the same
     * object. */
    tn5250_config_ref(config);
    if (This->config != NULL) {
        tn5250_config_unref(This->config);
    }
    This->config = config;
    return 0;
}

/****f* lib5250/tn5250_stream_destroy
 * NAME
 *    tn5250_stream_destroy
 * SYNOPSIS
 *    tn5250_stream_destroy (This);
 * INPUTS
 *    Tn5250Stream *       This       -
 * DESCRIPTION
 *    DOCUMENT ME!!!
 *****/
void tn5250_stream_destroy(Tn5250Stream* This) {
    /* Call particular stream type's destroy handler. */
    if (This->destroy) {
        (*(This->destroy))(This);
    }

    /* Free the environment. */
    if (This->config != NULL) {
        tn5250_config_unref(This->config);
    }
    tn5250_buffer_free(&(This->sb_buf));
    tn5250_record_list_destroy(This->records);
    free(This);
}

/****f* lib5250/tn5250_stream_get_record
 * NAME
 *    tn5250_stream_get_record
 * SYNOPSIS
 *    ret = tn5250_stream_get_record (This);
 * INPUTS
 *    Tn5250Stream *       This       -
 * DESCRIPTION
 *    DOCUMENT ME!!!
 *****/
Tn5250Record* tn5250_stream_get_record(Tn5250Stream* This) {
    Tn5250Record* record;
    int offset;

    record = This->records;
    TN5250_ASSERT(This->record_count >= 1);
    TN5250_ASSERT(record != NULL);

    This->records = tn5250_record_list_remove(This->records, record);
    This->record_count--;

    TN5250_ASSERT(tn5250_record_length(record) >= 10);
    offset = 6 + tn5250_record_data(record)[6];

    TN5250_LOG(("tn5250_stream_get_record: offset = %d\n", offset));
    tn5250_record_set_cur_pos(record, offset);

    return record;
}

/****f* lib5250/tn5250_stream_setenv
 * NAME
 *    tn5250_stream_setenv
 * SYNOPSIS
 *    tn5250_stream_setenv (This, name, value);
 * INPUTS
 *    Tn5250Stream *       This       -
 *    const char *         name       -
 *    const char *         value      -
 * DESCRIPTION
 *    Set an 'environment' string.  This is made to look like setenv().
 *****/
void tn5250_stream_setenv(Tn5250Stream* This, const char* name,
                          const char* value) {
    char* name_buf;
    if (This->config == NULL) {
        This->config = tn5250_config_new();
        TN5250_ASSERT(This->config != NULL);
    }
    name_buf = (char*)malloc(strlen(name) + 10);
    strcpy(name_buf, "env.");
    strcat(name_buf, name);
    tn5250_config_set(This->config, name_buf, value);
    free(name_buf);
}

/****f* lib5250/tn5250_stream_getenv
 * NAME
 *    tn5250_stream_getenv
 * SYNOPSIS
 *    ret = tn5250_stream_getenv (This, name);
 * INPUTS
 *    Tn5250Stream *       This       -
 *    const char *         name       -
 * DESCRIPTION
 *    Retrieve the value of a 5250 environment string.
 *****/
const char* tn5250_stream_getenv(Tn5250Stream* This, const char* name) {
    char* name_buf;
    const char* val;

    if (This->config == NULL) {
        return NULL;
    }

    name_buf = (char*)malloc(strlen(name) + 10);
    strcpy(name_buf, "env.");
    strcat(name_buf, name);
    val = tn5250_config_get(This->config, name_buf);
    free(name_buf);
    return val;
}

/****f* lib5250/tn5250_stream_unsetenv
 * NAME
 *    tn5250_stream_unsetenv
 * SYNOPSIS
 *    tn5250_stream_unsetenv (This, name);
 * INPUTS
 *    Tn5250Stream *       This       -
 *    const char *         name       -
 * DESCRIPTION
 *    Unset a 5250 environment string.
 *****/
void tn5250_stream_unsetenv(Tn5250Stream* This, const char* name) {
    char* name_buf;
    if (This->config == NULL) {
        return; /* Nothing to unset. */
    }

    name_buf = (char*)malloc(strlen(name) + 10);
    strcpy(name_buf, "env.");
    strcat(name_buf, name);
    tn5250_config_unset(This->config, name_buf);
    free(name_buf);
}

int tn5250_stream_socket_handle(Tn5250Stream* This) {
    return (int)This->sockfd;
}

int tn5250_stream_has_failed(Tn5250Stream* This) {
    return This->failed;
}

const char* tn5250_stream_last_startup_code(Tn5250Stream* This) {
    return This != NULL ? This->last_startup_code : "";
}

const char* tn5250_stream_devname_accepted(Tn5250Stream* This) {
    return This != NULL ? This->devname_accepted : "";
}

int tn5250_stream_devname_exhausted(Tn5250Stream* This) {
    return This != NULL ? This->devname_exhausted : 0;
}

/* RFC 1572 SEND. Private name: SEND is #defined only inside each transport,
 * and ESC here would be the 5250 escape (0x04), not NEW-ENVIRON ESC. */
#define TN5250_NEWENV_SEND 1

#define DEVNAME_MAX_ITEMS 64
#define DEVNAME_MAX_LEN   10

/* EBCDIC digits and capitals are the same in every CCSID we care about. */
static char devname_ebcdic_to_ascii(unsigned char b) {
    if (b >= 0xF0 && b <= 0xF9) {
        return (char)('0' + (b - 0xF0));
    }
    if (b >= 0xC1 && b <= 0xC9) {
        return (char)('A' + (b - 0xC1));
    }
    if (b >= 0xD1 && b <= 0xD9) {
        return (char)('J' + (b - 0xD1));
    }
    if (b >= 0xE2 && b <= 0xE9) {
        return (char)('S' + (b - 0xE2));
    }
    return '?';
}

/* 1 if list is 1..64 comma-separated items of 1..10 bytes in 0x20..0x7E. */
static int devname_list_is_valid(const char* list) {
    int items = 1;
    int len = 0;
    int i;

    for (i = 0;; i++) {
        unsigned char c = (unsigned char)list[i];
        if (c == '\0' || c == ',') {
            if (len == 0) {
                return 0;
            }
            if (c == '\0') {
                return 1;
            }
            if (++items > DEVNAME_MAX_ITEMS) {
                return 0;
            }
            len = 0;
            continue;
        }
        if (c < 0x20 || c > 0x7E || ++len > DEVNAME_MAX_LEN) {
            return 0;
        }
    }
}

/* Copies item `index` of a validated list into buf[11]; 0 if past the end. */
static int devname_candidate_at(const char* list, int index, char* buf) {
    int i = 0;
    int item = 0;
    int n = 0;

    for (;; i++) {
        char c = list[i];
        if (c == '\0' || c == ',') {
            if (item == index) {
                buf[n] = '\0';
                return 1;
            }
            if (c == '\0') {
                return 0;
            }
            item++;
            continue;
        }
        if (item == index && n < DEVNAME_MAX_LEN) {
            buf[n++] = c;
        }
    }
}

void tn5250_stream_note_record(Tn5250Stream* This, Tn5250Record* rec) {
    unsigned char raw[4];
    int i;

    if (This == NULL || rec == NULL ||
        !tn5250_record_startup_code(tn5250_record_data(rec),
                                    tn5250_record_length(rec), raw)) {
        return;
    }
    for (i = 0; i < 4; i++) {
        This->last_startup_code[i] = devname_ebcdic_to_ascii(raw[i]);
    }
    This->last_startup_code[4] = '\0';

    /* Only 8902 advances the walk. The flag is sticky: nothing but a SEND that
     * writes a new candidate clears it, so intervening records cannot hide a
     * refusal and a success cannot launder one. */
    if (raw[0] == 0xF8 && raw[1] == 0xF9 && raw[2] == 0xF0 && raw[3] == 0xF2) {
        This->devname_rejected = 1;
    }

    /* I904 is a failure (printsession.c), so not every I code counts. */
    if (This->devname_active && This->last_startup_code[0] == 'I' &&
        This->last_startup_code[1] == '9' && This->last_startup_code[2] == '0' &&
        (This->last_startup_code[3] == '1' ||
         This->last_startup_code[3] == '2' ||
         This->last_startup_code[3] == '6') &&
        This->config != NULL) {
        const char* cur = tn5250_config_get(This->config, "env.DEVNAME");
        if (cur != NULL && !This->devname_rejected && !This->devname_exhausted) {
            strncpy(This->devname_accepted, cur, DEVNAME_MAX_LEN);
            This->devname_accepted[DEVNAME_MAX_LEN] = '\0';
        }
    }
}

int tn5250_stream_devname_prepare(Tn5250Stream* This,
                                  const unsigned char* sb_buf, int sb_len) {
    const char* list;
    char buf[DEVNAME_MAX_LEN + 1];

    if (This->config == NULL) {
        return 0;
    }
    list = tn5250_config_get(This->config, "devname.candidates");
    if (list == NULL || !devname_list_is_valid(list)) {
        return 0;
    }
    if (This->devname_exhausted) {
        return 1;
    }
    /* Answer only a real SEND, so a refused name can never go out twice. */
    if (sb_len < 2 || sb_buf[1] != TN5250_NEWENV_SEND) {
        return 1;
    }
    /* A refusal before any candidate went out has nothing to skip. */
    if (This->devname_rejected && This->devname_active) {
        This->devname_index++;
    }
    if (!devname_candidate_at(list, This->devname_index, buf)) {
        This->devname_exhausted = 1;
        return 1;
    }
    /* buf is ours: config_set frees the old value before copying the new. */
    tn5250_config_set(This->config, "env.DEVNAME", buf);
    This->devname_rejected = 0;
    This->devname_active = 1;
    return 0;
}
