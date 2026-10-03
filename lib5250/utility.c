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
#include "transmaps.h"

/* ALPHA_ONLY validation and monocase upcasing need is-alpha/to-upper
   classification of a *local-charset* byte, which plain isalpha()/toupper()
   only get right for ASCII -- wrong for every accented Latin-1 letter and
   everything in a non-Latin charset. Classification is per-charset (9
   distinct ones across all 19 single-byte CCSIDs; several share a charset,
   e.g. every ISO-8859-1 one), generated offline by tools/gen_charclass.py
   rather than computed at runtime -- see that script's own comment for why
   it uses Python's stdlib codecs rather than vendoring, unlike
   tools/gen_charmaps.py on the rm-5250 side. Kept as a table keyed by
   map->name, not new fields on the public, ABI-published struct
   _Tn5250CharMap. */
typedef struct _Tn5250CharClass {
    const char* name;
    const unsigned char* is_alpha;
    const unsigned char* to_upper;
} Tn5250CharClass;

#include "charclass.h"

#if defined(__SVR4) && defined(__sun)
#include <sys/filio.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#endif

static unsigned char mapfix[256];
static unsigned char mapfix2[256];
static unsigned char mapfix3[256];
static unsigned char mapfix4[256];

#ifndef _WIN32

/****f* lp5250d/tn5250_closeall
 * NAME
 *    tn5250_closeall
 * SYNOPSIS
 *    tn5250_closeall (fd);
 * INPUTS
 *    int fd	- The starting file descriptor.
 * DESCRIPTION
 *    Closes all file descriptors >= a specified value.
 *****/
void tn5250_closeall(int fd) {
    int fdlimit = sysconf(_SC_OPEN_MAX);

    while (fd < fdlimit) {
        close(fd++);
    }
}

/*
  Signal handler for SIGCHLD.  We use waitpid instead of wait, since there
  is no way to tell wait not to block if there are still non-terminated child
  processes.
*/
void sig_child(int signum) {
    int pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        ;

    return;
}

/****f* lp5250d/tn5250_daemon
 * NAME
 *    tn5250_daemon
 * SYNOPSIS
 *    ret = tn5250_daemon (nochdir, noclose);
 * INPUTS
 *    int nochdir	- 0 to perform chdir.
 *    int noclose	- 0 to close all file handles.
 * DESCRIPTION
 *    Detach process from user and disappear into the background
 *    returns -1 on failure, but you can't do much except exit in that
 *    case since we may already have forked. Believed to work on all
 *    Posix systems.
 *****/
int tn5250_daemon(int nochdir, int noclose, int ignsigcld) {
    struct sigaction sa;

    switch (fork()) {
    case 0:
        break;
    case -1:
        return -1;
    default:
        _exit(0); /* exit the original process */
    }

    if (setsid() < 0) { /* shoudn't fail */
        return -1;
    }

    /* dyke out this switch if you want to acquire a control tty in */
    /* the future -- not normally advisable for daemons */

    switch (fork()) {
    case 0:
        break;
    case -1:
        return -1;
    default:
        _exit(0);
    }

    if (!nochdir) {
        chdir("/");
    }

    if (!noclose) {
        tn5250_closeall(0);
        open("/dev/null", O_RDWR);
        dup(0);
        dup(0);
    }

    umask(0);

    if (ignsigcld) {
        sa.sa_handler = sig_child;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;

#ifdef SIGCHLD
        sigaction(SIGCHLD, &sa, NULL);
#else
#ifdef SIGCLD
        sigaction(SIGCLD, &sa, NULL);
#endif
#endif
    }

    return 0;
}

#endif /* ifndef _WIN32 */

static struct {
    Tn5250ErrorType type;
    unsigned long code; // for compat with OpenSSL
} tn5250_error;

void _tn5250_set_error(Tn5250ErrorType type, int code) {
    tn5250_error.type = type;
    tn5250_error.code = code;
}

int tn5250_has_error(void) { return tn5250_error.type != TN5250_ERROR_UNKNOWN; }

void tn5250_clear_error(void) { _tn5250_set_error(0, 0); }

const char* tn5250_strerror(void) {
    if (tn5250_error.type == TN5250_ERROR_ERRNO) {
        return strerror(tn5250_error.code);
    }
    else if (tn5250_error.type == TN5250_ERROR_GAI) {
        return gai_strerror(tn5250_error.code);
    }
#ifdef HAVE_LIBSSL
    else if (tn5250_error.type == TN5250_ERROR_SSL) {
        return ERR_error_string(tn5250_error.code, NULL);
    }
#endif
    else if (tn5250_error.type == TN5250_ERROR_INTERNAL) {
        switch (tn5250_error.code) {
        case TN5250_INTERNALERROR_INVALIDADDRESS:
            return "Invalid address";
        case TN5250_INTERNALERROR_INVALIDCERT:
            return "Certificate verification failure";
        }
    }
    return NULL;
}

/****f* lib5250/tn5250_char_map_to_remote
 * NAME
 *    tn5250_char_map_to_remote
 * SYNOPSIS
 *    ret = tn5250_char_map_to_remote (map,ascii);
 * INPUTS
 *    Tn5250Char           ascii      - The local character to translate.
 * DESCRIPTION
 *    Translate the specified character from local to remote.
 *****/
Tn5250Char tn5250_char_map_to_remote(Tn5250CharMap* map, Tn5250Char ascii) {
    return map->to_remote_map[ascii];
}

/****f* lib5250/tn5250_char_map_to_local
 * NAME
 *    tn5250_char_map_to_local
 * SYNOPSIS
 *    local = tn5250_char_map_to_local (map, ebcdic);
 * INPUTS
 *    Tn5250Char           ebcdic     - The remote character to translate.
 * DESCRIPTION
 *    Translate the specified character from remote character to local.
 *****/
Tn5250Char tn5250_char_map_to_local(Tn5250CharMap* map, Tn5250Char ebcdic) {
    switch (ebcdic) {
    case 0x1C:
        return '*'; /* This should be an overstriken asterisk (DUP) */
    case 0:
        return ' ';
    default:
        return map->to_local_map[ebcdic];
    }
}

/* XXX: HACK: These characters were reported wrong in transmaps.h.
        Since that's a generated file, I'm overriding them here -SCK

   Factored out of tn5250_char_map_new() so tn5250_char_map_new_exact()
   (below) can share it exactly rather than risk a second, divergent copy --
   this installs the correction into *both* the "870" and "win870" entries
   of the global tn5250_transmaps[] table regardless of which one was asked
   for, same as the original always did. */
static void install_870_workaround(const char* map) {
    Tn5250CharMap* t;

    if (strcmp(map, "870") != 0 && strcmp(map, "win870") != 0) {
        return;
    }

    TN5250_LOG(("install_870_workaround: Installing 870 workaround\n"));

    memcpy(mapfix, windows_1250_to_ibm870, sizeof(mapfix));
    memcpy(mapfix2, ibm870_to_windows_1250, sizeof(mapfix2));
    memcpy(mapfix3, iso_8859_2_to_ibm870, sizeof(mapfix3));
    memcpy(mapfix4, ibm870_to_iso_8859_2, sizeof(mapfix4));

    mapfix[142] = 184;
    mapfix[143] = 185;
    mapfix[158] = 182;
    mapfix[159] = 183;
    mapfix[163] = 186;
    mapfix[202] = 114;
    mapfix[234] = 82;

    mapfix2[82] = 234;
    mapfix2[114] = 202;
    mapfix2[182] = 158;
    mapfix2[183] = 159;
    mapfix2[184] = 142;
    mapfix2[185] = 143;
    mapfix2[186] = 163;

    mapfix3[163] = 186;
    mapfix3[172] = 185;
    mapfix3[188] = 183;
    mapfix3[202] = 114;
    mapfix3[234] = 82;

    mapfix4[82] = 234;
    mapfix4[114] = 202;
    mapfix4[183] = 188;
    mapfix4[185] = 172;
    mapfix4[186] = 163;

    for (t = tn5250_transmaps; t->name; t++) {
        if (!strcmp(t->name, "win870")) {
            t->to_remote_map = mapfix;
            t->to_local_map = mapfix2;
            TN5250_LOG(("Workaround installed for map \"win870\"\n"));
        }
        else if (!strcmp(t->name, "870")) {
            t->to_remote_map = mapfix3;
            t->to_local_map = mapfix4;
            TN5250_LOG(("Workaround installed for map \"870\"\n"));
        }
    }
}

/* The plain exact-name lookup both tn5250_char_map_new() and
   tn5250_char_map_new_exact() fall through to -- factored out so the two
   stay trivially in sync with each other. */
static Tn5250CharMap* lookup_exact(const char* map) {
    Tn5250CharMap* t;

    for (t = tn5250_transmaps; t->name; t++) {
        if (strcmp(t->name, map) == 0) {
            return t;
        }
    }
    return NULL;
}

/* NULL for a NULL map, or an unknown/"win"-prefixed name
   (tn5250_char_map_new_exact() never resolves one of those, but
   tn5250_char_map_is_alpha()/tn5250_char_map_to_upper() below fall back to
   plain ASCII isalpha()/toupper() in that case, same as if no map had been
   generated for it at all -- fail-safe by construction, not merely by the
   current absence of a caller that could reach here with one). Takes the
   map itself, not just its name, so both call sites below do the same
   NULL check once rather than each repeating it inline. */
static const Tn5250CharClass* lookup_charclass(Tn5250CharMap* map) {
    const Tn5250CharClass* c;

    if (map == NULL) {
        return NULL;
    }
    for (c = tn5250_charclasses; c->name; c++) {
        if (strcmp(c->name, map->name) == 0) {
            return c;
        }
    }
    return NULL;
}

/****f* lib5250/tn5250_char_map_new
 * NAME
 *    tn5250_char_map_new
 * SYNOPSIS
 *    cmap = tn5250_char_map_new ("37");
 * INPUTS
 *    const char *         map        - Name of the character translation map.
 * DESCRIPTION
 *    Create a new translation map.
 * NOTES
 *    Translation maps are currently statically allocated, although you should
 *    call tn5250_char_map_destroy (a no-op) for future compatibility.
 *****/
Tn5250CharMap* tn5250_char_map_new(const char* map) {
    TN5250_LOG(("tn5250_char_map_new: map = \"%s\"\n", map));

    install_870_workaround(map);

    /* Under Windows, we'll try the "winXXX" maps first, then fall back
       to the standard (unix) versions */
#ifdef _WIN32
    {
        char winmap[10];
        Tn5250CharMap* t;
        _snprintf(winmap, sizeof(winmap) - 1, "win%s", map);
        for (t = tn5250_transmaps; t->name; t++) {
            if (strcmp(t->name, winmap) == 0) {
                TN5250_LOG(("Using map %s\n", t->name));
                return t;
            }
        }
    }
#endif

    return lookup_exact(map);
}

/****f* lib5250/tn5250_char_map_new_exact
 * NAME
 *    tn5250_char_map_new_exact
 * SYNOPSIS
 *    cmap = tn5250_char_map_new_exact ("870");
 * INPUTS
 *    const char *         map        - Name of the character translation map.
 * DESCRIPTION
 *    Identical to tn5250_char_map_new(), except it never substitutes a
 *    "win"-prefixed table on Windows: it always returns the table for the
 *    exact name given. Added for rm-5250, whose EBCDIC->Unicode display
 *    table is generated once from the non-"win" tables and shipped
 *    identically on every platform (see tools/gen_charmaps.py in rm-5250
 *    itself) -- letting input silently follow a different, "win"-prefixed
 *    table on Windows would make typed/pasted characters round-trip to a
 *    different EBCDIC byte than what the very same codepoint displays as,
 *    for several of the non-Latin-1 code pages (confirmed: this is not a
 *    narrow issue -- every "win"-prefixed table in transmaps.h disagrees
 *    with its non-"win" counterpart at some position, drastically so for
 *    win420/ibm420, over a quarter of the printable byte range).
 *
 *    This is a policy choice specific to an embedder with exactly one
 *    display table shared across platforms, not a correctness fix to
 *    tn5250_char_map_new() itself -- a different embedder rendering
 *    through the host OS's own native code page may still legitimately
 *    want the "win"-preferring behaviour that function keeps unchanged.
 * NOTES
 *    Same allocation/destruction contract as tn5250_char_map_new().
 *****/
Tn5250CharMap* tn5250_char_map_new_exact(const char* map) {
    TN5250_LOG(("tn5250_char_map_new_exact: map = \"%s\"\n", map));
    install_870_workaround(map);
    return lookup_exact(map);
}

/****f* lib5250/tn5250_char_map_destroy
 * NAME
 *    tn5250_char_map_destroy
 * SYNOPSIS
 *    tn5250_char_map_destroy (map);
 * INPUTS
 *    Tn5250CharMap *         map     - The character map to destroy.
 * DESCRIPTION
 *    Frees the character map's resources.
 *****/
void tn5250_char_map_destroy(Tn5250CharMap* map) { /* NOOP */
}

/****f* lib5250/tn5250_char_map_printable_p
 * NAME
 *    tn5250_char_map_printable_p
 * SYNOPSIS
 *    if (tn5250_char_map_printable_p (map,ec))
 *	 ;
 * INPUTS
 *    Tn5250CharMap *      map        - the character map to use.
 *    Tn5250Char           ec         - the character to test.
 * DESCRIPTION
 *    Determines whether the specified character is printable, which means
 *    either it is a displayable EBCDIC character, an ideographic control
 *    character, a NUL, or a few other odds and ends.
 * SOURCE
 */
int tn5250_char_map_printable_p(Tn5250CharMap* map, Tn5250Char data) {
    switch (data) {
        /*
           Ideographic Shift-In and Shift-Out.
           case 0x0e:
           case 0x0f:
        */
    default:
        break;
    }
    return 1;
}
/*******/

/****f* lib5250/tn5250_char_map_attribute_p
 * NAME
 *    tn5250_char_map_attribute_p
 * SYNOPSIS
 *    ret = tn5250_char_map_attribute_p (map,ec);
 * INPUTS
 *    Tn5250CharMap *      map        - the translation map to use.
 *    Tn5250Char           ec         - the character to test.
 * DESCRIPTION
 *    Determines whether the character is a 5250 attribute.
 *****/
int tn5250_char_map_attribute_p(Tn5250CharMap* map, Tn5250Char data) {
    return ((data & 0xE0) == 0x20);
}

/****f* lib5250/tn5250_char_map_is_alpha
 * NAME
 *    tn5250_char_map_is_alpha
 * SYNOPSIS
 *    if (tn5250_char_map_is_alpha (map, ch))
 *       ;
 * INPUTS
 *    Tn5250CharMap *      map        - the character map ch is local to, or
 *                                       NULL for plain ASCII classification.
 *    unsigned char        ch         - the local-charset byte to classify.
 * DESCRIPTION
 *    Is ch alphabetic in the local charset map was generated for? Unlike
 *    isalpha(3), correct for every one of this library's 9 distinct
 *    single-byte local charsets, not just ASCII -- see
 *    tools/gen_charclass.py. map == NULL, or a map this function does not
 *    have a table for (a "win"-prefixed name, or one the generator does not
 *    cover), falls back to plain isalpha(), i.e. today's prior behaviour.
 *****/
int tn5250_char_map_is_alpha(Tn5250CharMap* map, unsigned char ch) {
    const Tn5250CharClass* cls = lookup_charclass(map);

    if (cls == NULL) {
        return isalpha(ch) != 0;
    }
    return cls->is_alpha[ch] != 0;
}
/*******/

/****f* lib5250/tn5250_char_map_to_upper
 * NAME
 *    tn5250_char_map_to_upper
 * SYNOPSIS
 *    ch = tn5250_char_map_to_upper (map, ch);
 * INPUTS
 *    Tn5250CharMap *      map        - the character map ch is local to, or
 *                                       NULL for plain ASCII upcasing.
 *    unsigned char        ch         - the local-charset byte to upcase.
 * DESCRIPTION
 *    The uppercase form of ch in the local charset map was generated for,
 *    or ch unchanged if it has none (not alphabetic, already uppercase, or
 *    this specific charset has no single-byte uppercase form for it).
 *
 *    Gated on this specific map's own round trip, not merely the per-
 *    charset table: to_upper[] is shared by every CCSID using the same
 *    charset, but to_remote_map/to_local_map are per-CCSID, and a handful
 *    of bytes a charset can represent are not actually reachable on every
 *    CCSID built from it (e.g. CCSID 870 cannot represent two ISO-8859-2
 *    letters its own charset otherwise has -- see
 *    latin2sOrphanedCharactersAreCorrectlyUnrepresentable() on the rm-5250
 *    side). Upcasing to a byte this map cannot actually round-trip would
 *    silently substitute a different character than the one asked for, so
 *    it is left unchanged instead if that happens. map == NULL, or a map
 *    with no table (same cases as tn5250_char_map_is_alpha()), falls back
 *    to plain toupper().
 *****/
unsigned char tn5250_char_map_to_upper(Tn5250CharMap* map, unsigned char ch) {
    const Tn5250CharClass* cls = lookup_charclass(map);
    unsigned char upper;

    if (cls == NULL) {
        return (unsigned char)toupper(ch);
    }
    upper = cls->to_upper[ch];
    if (upper == ch) {
        return ch;
    }
    /* Deliberately the raw to_remote_map/to_local_map arrays, not
       tn5250_char_map_to_remote()/to_local() -- this is a round-trip
       identity check on the *table data*, and those two functions' extra
       special cases (EBCDIC 0x1C -> DUP, 0x00 -> space) have nothing to do
       with whether `upper` survives a plain table round trip. */
    if (map->to_local_map[map->to_remote_map[upper]] == upper) {
        return upper;
    }
    return ch;
}
/*******/

#ifndef NDEBUG
FILE* tn5250_logfile = NULL;

/****f* lib5250/tn5250_log_open
 * NAME
 *    tn5250_log_open
 * SYNOPSIS
 *    tn5250_log_open (fname);
 * INPUTS
 *    const char *         fname      - Filename of tracefile.
 * DESCRIPTION
 *    Opens the debug tracefile for this session.
 *****/
void tn5250_log_open(const char* fname) {
    if (tn5250_logfile != NULL) {
        fclose(tn5250_logfile);
    }
    tn5250_logfile = fopen(fname, "w");
    if (tn5250_logfile == NULL) {
        perror(fname);
        exit(1);
    }
    /* FIXME: Write $TERM, version, and uname -a to the file. */
#ifndef _WIN32
    /* Set file mode to 0600 since it may contain passwords. */
    fchmod(fileno(tn5250_logfile), 0600);
#endif
    setbuf(tn5250_logfile, NULL);
}

/****f* lib5250/tn5250_log_close
 * NAME
 *    tn5250_log_close
 * SYNOPSIS
 *    tn5250_log_close ();
 * INPUTS
 *    None
 * DESCRIPTION
 *    Close the current tracefile if one is open.
 *****/
void tn5250_log_close() {
    if (tn5250_logfile != NULL) {
        fclose(tn5250_logfile);
        tn5250_logfile = NULL;
    }
}

/****f* lib5250/tn5250_log_printf
 * NAME
 *    tn5250_log_printf
 * SYNOPSIS
 *    tn5250_log_printf (fmt, );
 * INPUTS
 *    const char *         fmt        -
 * DESCRIPTION
 *    This is an internal function called by the TN5250_LOG() macro.  Use
 *    the macro instead, since it can be conditionally compiled.
 *****/
void tn5250_log_printf(const char* fmt, ...) {
    va_list vl;
    if (tn5250_logfile != NULL) {
        va_start(vl, fmt);
        vfprintf(tn5250_logfile, fmt, vl);
        va_end(vl);
    }
}

/****f* lib5250/tn5250_log_assert
 * NAME
 *    tn5250_log_assert
 * SYNOPSIS
 *    tn5250_log_assert (val, expr, file, line);
 * INPUTS
 *    int                  val        -
 *    char const *         expr       -
 *    char const *         file       -
 *    int                  line       -
 * DESCRIPTION
 *    This is an internal function called by the TN5250_ASSERT() macro.  Use
 *    the macro instead, since it can be conditionally compiled.
 *****/
void tn5250_log_assert(int val, char const* expr, char const* file, int line) {
    if (!val) {
        tn5250_log_printf("\nAssertion %s failed at %s, line %d.\n", expr, file,
                          line);
        fprintf(stderr, "\nAssertion %s failed at %s, line %d.\n", expr, file,
                line);
        abort();
    }
}
#endif /* NDEBUG */

/****f* lib5250/tn5250_parse_color
 * NAME
 *    tn5250_parse_color
 * SYNOPSIS
 *    tn5250_parse_color (config, "green", &red, &green, &blue);
 * INPUTS
 *    Tn5250Config *       config     -
 *    const char   *       colorname  -
 *    int          *       red        -
 *    int          *       green      -
 *    int          *       blue       -
 * DESCRIPTION
 *    This loads a color from the TN5250 config object, and then
 *    parses it into it's red, green, blue components.
 *****/
int tn5250_parse_color(Tn5250Config* config, const char* colorname, int* red,
                       int* green, int* blue) {

    const char* p;
    char colorspec[16];
    int r, g, b;

    if ((p = tn5250_config_get(config, colorname)) == NULL) {
        return -1;
    }

    strncpy(colorspec, p, sizeof(colorspec));
    colorspec[sizeof(colorspec) - 1] = '\0';

    if (*colorspec != '#') {
        if (!strcasecmp(colorspec, "white")) {
            r = 255;
            g = 255;
            b = 255;
        }
        else if (!strcasecmp(colorspec, "yellow")) {
            r = 255;
            g = 255;
            b = 0;
        }
        else if (!strcasecmp(colorspec, "lightmagenta")) {
            r = 255;
            g = 0;
            b = 255;
        }
        else if (!strcasecmp(colorspec, "lightred")) {
            r = 255;
            g = 0;
            b = 0;
        }
        else if (!strcasecmp(colorspec, "lightcyan")) {
            r = 0;
            g = 255;
            b = 255;
        }
        else if (!strcasecmp(colorspec, "lightgreen")) {
            r = 0;
            g = 255;
            b = 0;
        }
        else if (!strcasecmp(colorspec, "lightblue")) {
            r = 0;
            g = 0;
            b = 255;
        }
        else if (!strcasecmp(colorspec, "lightgray")) {
            r = 192;
            g = 192;
            b = 192;
        }
        else if (!strcasecmp(colorspec, "gray")) {
            r = 128;
            g = 128;
            b = 128;
        }
        else if (!strcasecmp(colorspec, "brown")) {
            r = 128;
            g = 128;
            b = 0;
        }
        else if (!strcasecmp(colorspec, "red")) {
            r = 128;
            g = 0;
            b = 0;
        }
        else if (!strcasecmp(colorspec, "cyan")) {
            r = 0;
            g = 128;
            b = 128;
        }
        else if (!strcasecmp(colorspec, "green")) {
            r = 0;
            g = 128;
            b = 0;
        }
        else if (!strcasecmp(colorspec, "blue")) {
            r = 0;
            g = 0;
            b = 128;
        }
        else if (!strcasecmp(colorspec, "black")) {
            r = 0;
            g = 0;
            b = 0;
        }
    }
    else {
        if (strlen(colorspec) != 7) {
            return -1;
        }
        if (sscanf(&colorspec[1], "%02x%02x%02x", &r, &g, &b) != 3) {
            return -1;
        }
    }

    *red = r;
    *green = g;
    *blue = b;
    return 0;
}

/****f* lib5250/tn5250_run_cmd
 * NAME
 *    tn5250_run_cmd
 * SYNOPSIS
 *    tn5250_run_cmd ("notepad", 0);
 * INPUTS
 *    const char   *       cmd        -
 *    int                  wait       -
 * DESCRIPTION
 *    Run a command (submitted to us by the AS/400)
 *****/
#ifndef _WIN32
int tn5250_run_cmd(const char* cmd, int wait) {

    struct sigaction sa;
    int sig;
    int cpid;

    sa.sa_handler = sig_child;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

#ifdef SIGCHLD
    sigaction(SIGCHLD, &sa, NULL);
#else
#ifdef SIGCLD
    sigaction(SIGCLD, &sa, NULL);
#endif
#endif

    switch (cpid = fork()) {
    case -1:
        return -1;

    case 0:
        system(cmd);
        _exit(0);
    }

    if (wait) {
        waitpid(cpid, NULL, 0);
    }

    return 0;
}
#endif

#ifdef _WIN32
int win32_run_process(const char* cmd, int wait);

int tn5250_run_cmd(const char* cmd, int wait) {

    char* tempcmd;
    char* prefix = "cmd.exe /c ";
    int rc;

    rc = win32_run_process(cmd, wait);

    if (rc == -1) {

        tempcmd = malloc(strlen(prefix) + strlen(cmd) + 1);
        strcpy(tempcmd, prefix);
        strcat(tempcmd, cmd);

        rc = win32_run_process(tempcmd, wait);
        free(tempcmd);
    }

    return rc;
}

int win32_run_process(const char* cmd, int wait) {

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(si));
    si.cb = sizeof(si);

    if (!CreateProcess(NULL,        /* no module name */
                       (LPTSTR)cmd, /* command line */
                       NULL,        /* don't inherit process bandle */
                       NULL,        /* don't inherit thread handle */
                       FALSE,       /* no inheritance, by golly! */
                       0,           /* flags */
                       NULL,        /* use parent's environment */
                       NULL,        /* use parent's directory */
                       &si,         /* STARTUPINFO */
                       &pi)) {      /* PROCESS_INFORMATION */
        return -1;
    }

    if (wait) {
        WaitForSingleObject(pi.hProcess, INFINITE);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

#endif /* ifdef _WIN32 */
