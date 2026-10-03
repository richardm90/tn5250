#!/usr/bin/env python3
"""Generate lib5250/charclass.h: is-alpha/to-upper classification tables for
ALPHA_ONLY field validation and monocase upcasing, replacing a plain
isalpha()/toupper() call on a local-charset byte -- ASCII-only, and so wrong
for every accented Latin-1 letter and everything in a non-Latin charset.

Classification is computed entirely offline, from Python's own
str.isalpha()/str.upper() over the real decoded character, for each of the 9
distinct local charsets rm-5250's input direction can produce (ISO-8859-
1/2/3/5/6/7/8/9, and JIS X0201 half-width katakana) -- not per-CCSID, since
several CCSIDs share the same local charset (all eleven ISO-8859-1 ones).
Deliberately no iswalpha()/towupper()/setlocale() anywhere here or in the C
this generates: `ch` is a byte in a charset chosen by the host's CCSID,
unrelated to the process's own locale.

A local byte with no character defined in its charset at all (several exist
in ISO-8859-3/6/7/8 -- Arabic and Hebrew use far fewer than 256 positions)
is classified not-alpha, self-upper -- the same "absent, not guessed"
convention tools/gen_charmaps.py uses on the display side.

Case folding is Python's plain str.upper() on every charset, including
905/1026's Turkish-associated ISO-8859-3/9 -- deliberately *not* Unicode's
Turkish-specific i/İ/ı/I SpecialCasing.txt rule, which an earlier version
of this generator did apply. Reverted after real-host testing: a monocase
IBM i field (a user ID, a device name, a program name) is a structured
ASCII identifier, not free Turkish prose, and silently turning a typed
lowercase 'i' into 'İ' -- a different EBCDIC byte than plain 'I' -- broke
logging in with a username containing the letter.

Run after transmaps.h changes (it does not read transmaps.h itself -- the
charset-to-CCSID-name mapping below, CHARSETS, is instead hand-verified
against tn5250_transmaps[] and must stay that way):
  python3 tools/gen_charclass.py
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "lib5250/charclass.h"

# (C identifier, Python codec name or None for JIS X0201's hand-written
# decode below, [CCSID names from lib5250/transmaps.h sharing this
# charset]). Every non-"win"-prefixed single-byte entry in tn5250_transmaps[]
# must appear exactly once across these lists.
CHARSETS = [
    ("iso_8859_1", "iso8859_1",
     ["37", "256", "273", "277", "278", "280", "284", "285", "297", "500", "871"]),
    ("iso_8859_2", "iso8859_2", ["870"]),
    ("iso_8859_3", "iso8859_3", ["905"]),
    ("iso_8859_5", "iso8859_5", ["880"]),
    ("iso_8859_6", "iso8859_6", ["420"]),
    ("iso_8859_7", "iso8859_7", ["875"]),
    ("iso_8859_8", "iso8859_8", ["424"]),
    ("iso_8859_9", "iso8859_9", ["1026"]),
    ("jis_x0201", None, ["290"]),  # no exact Python codec; see decode_jis_x0201()
]

def decode_jis_x0201(byte):
    """JIS X0201: ASCII/half-width-katakana layout, with two real
    differences from Shift_JIS/cp932's reading of the same byte positions --
    0x5C is YEN SIGN, not backslash; 0x7E is OVERLINE, not tilde. Neither
    position is alphabetic under either reading, so this correction changes
    no classification outcome; it exists so the generated table's
    *codepoints* describe real JIS X0201 rather than a Shift_JIS
    approximation that is silently wrong in two places. Returns None for a
    byte with no standalone meaning (a Shift_JIS lead byte)."""
    if byte == 0x5C:
        return "¥"
    if byte == 0x7E:
        return "‾"
    try:
        return bytes([byte]).decode("shift_jis")
    except UnicodeDecodeError:
        return None


def build_table(ident, codec):
    is_alpha = [0] * 256
    to_upper = list(range(256))  # identity unless a real uppercase byte is found below

    # JIS X0201 has no stdlib codec to .encode() an uppercase character back
    # into a byte (decode_jis_x0201() is a one-way, hand-written decode) --
    # built once, lowest byte wins on a tie, same "first wins" rule
    # buildReverse() uses on the rm-5250 side for an analogous case.
    jis_reverse = None
    if codec is None:
        jis_reverse = {}
        for byte in range(256):
            decoded = decode_jis_x0201(byte)
            if decoded is not None and decoded not in jis_reverse:
                jis_reverse[decoded] = byte

    for byte in range(256):
        if codec is not None:
            try:
                ch = bytes([byte]).decode(codec)
            except UnicodeDecodeError:
                continue  # undefined in this charset -- not alpha, self-upper
        else:
            ch = decode_jis_x0201(byte)
            if ch is None:
                continue

        if ch.isalpha():
            is_alpha[byte] = 1

        upper = ch.upper()

        if len(upper) != 1 or upper == ch:
            continue  # no single-character uppercase form, or already upper

        if codec is None:
            upper_byte = jis_reverse.get(upper)
            if upper_byte is None:
                continue  # this charset has no byte for the uppercase form
            to_upper[byte] = upper_byte
            continue

        try:
            upper_bytes = upper.encode(codec)
        except UnicodeEncodeError:
            continue  # this charset has no byte for the uppercase form
        if len(upper_bytes) != 1:
            continue
        to_upper[byte] = upper_bytes[0]

    return is_alpha, to_upper


def check_consistency(ident, is_alpha, to_upper):
    """display.c upcases before it validates
    (tn5250_display_interactive_addch(): monocase upcase, then
    tn5250_field_valid_char_map()) -- if upcasing ever produced a byte this
    same table doesn't call alpha, a monocase ALPHA_ONLY field would reject
    a character immediately after silently transforming it. Must hold for
    every charset before this is trustworthy at runtime."""
    for byte in range(256):
        upper = to_upper[byte]
        if upper != byte and not is_alpha[upper]:
            sys.exit(
                f"{ident}: byte 0x{byte:02X} upcases to 0x{upper:02X}, which "
                "this table does not classify as alpha -- generator bug"
            )

    # All 9 charsets contain plain ASCII in their lower half (even JIS
    # X0201, whose own repertoire is half-width katakana, not Latin) -- a
    # hard, unconditional invariant, not a heuristic, and exactly the shape
    # of bug (a whole charset's to_upper silently staying identity) that
    # slipped past the check above once already for jis_x0201. No exception
    # for CCSID 905/1026 ('i' included): a monocase IBM i field is a
    # structured ASCII identifier (a user ID, a device name, a program
    # name), not free Turkish prose, and silently turning a typed 'i' into
    # 'İ' -- a different EBCDIC byte -- broke logging in with a username
    # containing the letter, confirmed against a real host. Plain ASCII
    # case folding applies uniformly on every one of the 9 charsets.
    for byte in range(ord("a"), ord("z") + 1):
        if not is_alpha[byte] or not is_alpha[byte - 32]:
            sys.exit(f"{ident}: plain ASCII byte 0x{byte:02X}/0x{byte - 32:02X} "
                      "not classified alpha -- generator bug")
        if to_upper[byte] != byte - 32:
            sys.exit(f"{ident}: plain ASCII byte 0x{byte:02X} upcases to "
                      f"0x{to_upper[byte]:02X}, not 0x{byte - 32:02X} -- generator bug")


def write_array(lines, name, values):
    lines.append(f"static const unsigned char {name}[256] = {{")
    for row in range(16):
        chunk = ", ".join(str(values[row * 16 + col]) for col in range(16))
        lines.append(f"    {chunk},")
    lines.append("};")
    lines.append("")


def main():
    lines = [
        "/* charclass.h was generated by tools/gen_charclass.py.",
        "   Any changes should be made there and NOT in this file! */",
        "",
        "// clang-format off",
    ]
    class_entries = []
    for ident, codec, ccsid_names in CHARSETS:
        is_alpha, to_upper = build_table(ident, codec)
        check_consistency(ident, is_alpha, to_upper)
        write_array(lines, f"{ident}_is_alpha", is_alpha)
        write_array(lines, f"{ident}_to_upper", to_upper)
        for name in ccsid_names:
            class_entries.append((name, ident))

    lines.append("static const Tn5250CharClass tn5250_charclasses[] = {")
    for name, ident in class_entries:
        lines.append(f'    {{ "{name}", {ident}_is_alpha, {ident}_to_upper }},')
    lines.append("    { NULL, NULL, NULL },")
    lines.append("};")
    lines.append("// clang-format on")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {len(class_entries)} CCSID entries across {len(CHARSETS)} charsets to {OUT}")


if __name__ == "__main__":
    main()
