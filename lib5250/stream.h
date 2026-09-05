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
#ifndef STREAM5250_H
#define STREAM5250_H

#if _WIN32
#include <winsock2.h> /* Need for SOCKET type.  GJS 3/3/2000 */
#endif

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct _Tn5250Config;

struct Tn5250Header {
    int flowtype;
    unsigned char flags;
    unsigned char opcode;
};

typedef struct Tn5250Header StreamHeader;

/****s* lib5250/Tn5250Stream
 * NAME
 *    Tn5250Stream
 * SYNOPSIS
 *    Tn5250Stream *str = tn5250_stream_open ("telnet:my.as400.com");
 *    Tn5250Record *rec;
 *    tn5250_stream_send_packet (str, 0, TN5250_RECORD_FLOW_DISPLAY,
 *	 TN5250_RECORD_H_NONE, TN5250_RECORD_OPCODE_PUT_GET, NULL);
 *    rec = tn5250_stream_get_record (str);
 *    tn5250_stream_disconnect (str);
 *    tn5250_stream_destroy (str);
 * DESCRIPTION
 *    Tn5250Stream is 'abstract', implementations currently reside in
 *    the telnetstr.c and debug.c source files.  A stream object
 *    manages the communications transport, such as TCP/IP.
 * SOURCE
 */
struct _Tn5250Stream;
typedef struct _Tn5250Stream Tn5250Stream;
/******/

extern Tn5250Stream /*@only@*/ /*@null@*/*
tn5250_stream_open(const char* to, struct _Tn5250Config* config);
extern int tn5250_stream_config(Tn5250Stream* This,
                                struct _Tn5250Config* config);
extern void tn5250_stream_destroy(Tn5250Stream /*@only@*/* This);
extern Tn5250Record /*@only@*/* tn5250_stream_get_record(Tn5250Stream* This);
#define tn5250_stream_connect(This, to)    (*(This->connect))((This), (to))
#define tn5250_stream_disconnect(This)     (*(This->disconnect))((This))
#define tn5250_stream_handle_receive(This) (*(This->handle_receive))((This))
#define tn5250_stream_send_packet(This, len, header, data)                     \
    (*(This->send_packet))((This), (len), (header), (data))

/* This should be a more flexible replacement for different NEW_ENVIRON
 * strings. */
extern void tn5250_stream_setenv(Tn5250Stream* This, const char* name,
                                 const char /*@null@*/* value);
extern void tn5250_stream_unsetenv(Tn5250Stream* This, const char* name);
extern /*@observer@*/ /*@null@*/ const char*
tn5250_stream_getenv(Tn5250Stream* This, const char* name);

#define tn5250_stream_record_count(This) ((This)->record_count)
extern int tn5250_stream_socket_handle(Tn5250Stream* This);

/****s* lib5250/Tn5250PeerCertInfo
 * NAME
 *    Tn5250PeerCertInfo
 * DESCRIPTION
 *    A snapshot of the TLS leaf certificate a server presented, taken once
 *    at connect time. Deliberately plain C types only (no OpenSSL type
 *    anywhere in this struct or the function below) so that code built
 *    without HAVE_LIBSSL visibility -- which is every consumer outside
 *    lib5250 itself, since that define is private to this library's own
 *    build -- can still declare and call tn5250_stream_get_peer_cert_info()
 *    unconditionally. This is for trust-on-first-use pinning of the leaf
 *    certificate's content, not chain verification: nothing here says
 *    whether the certificate is valid against any CA, only what it says
 *    about itself.
 * SOURCE
 */
/* A named tag (not an anonymous struct), matching how _Tn5250Stream/
 * Tn5250Stream is done just above -- so a consumer header can forward-
 * declare `struct _Tn5250PeerCertInfo;` without including this header at
 * all, the same way term.h forward-declares every other lib5250 type
 * rather than including lib5250.h itself. */
struct _Tn5250PeerCertInfo {
    unsigned char sha256[32]; /* SHA-256 of the leaf cert's DER encoding --
                                * this is what gets pinned. */
    char subject[256];        /* X509_NAME_oneline() of the subject, truncated */
    char issuer[256];         /* ...of the issuer */
    char serialHex[64];
    char pubKeyType[32];      /* e.g. "RSA 2048-bit", "EC 256-bit" */
    char notBefore[64];
    char notAfter[64];
};
typedef struct _Tn5250PeerCertInfo Tn5250PeerCertInfo;
/******/

/****f* lib5250/tn5250_stream_get_peer_cert_info
 * NAME
 *    tn5250_stream_get_peer_cert_info
 * SYNOPSIS
 *    rc = tn5250_stream_get_peer_cert_info (This, &info);
 * DESCRIPTION
 *    Fetch a snapshot of the TLS leaf certificate presented by the server
 *    This is connected to. Returns:
 *      0 -- an SSL stream with a certificate available; info is filled in.
 *      1 -- not an SSL stream (e.g. plain telnet). info is untouched; the
 *           caller should skip certificate-pinning entirely, exactly as
 *           it would have before this function existed.
 *      2 -- an SSL stream, but no certificate could be read. info is
 *           untouched. Callers MUST treat this as a hard failure, not as
 *           equivalent to case 1 -- silently skipping pinning here would
 *           make a security-relevant check fail open.
 *****/
extern int tn5250_stream_get_peer_cert_info(Tn5250Stream* This,
                                            Tn5250PeerCertInfo* info);

#ifdef __cplusplus
}

#endif
#endif
