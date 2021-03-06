/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */

#ifndef __ELS_SRVC__
#define __ELS_SRVC__

#include <windef.h>

/* https://docs.microsoft.com/en-us/windows/win32/intl/transliteration-services */

static const GUID ELS_GUID_LANGUAGE_DETECTION = { 0xcf7e00b1, 0x909b, 0x4d95, { 0xa8, 0xf4, 0x61, 0x1f, 0x7c, 0x37, 0x77, 0x02 } };
static const GUID ELS_GUID_SCRIPT_DETECTION = { 0x2d64b439, 0x6caf, 0x4f6b, { 0xb6, 0x88, 0xe5, 0xd0, 0xf4, 0xfa, 0xa7, 0xd7 } };
static const GUID ELS_GUID_TRANSLITERATION_HANT_TO_HANS = { 0xa3a8333b, 0xf4fc, 0x42f6, { 0xa0, 0xc4, 0x04, 0x62, 0xfe, 0x73, 0x17, 0xcb } };
static const GUID ELS_GUID_TRANSLITERATION_HANS_TO_HANT = { 0x3caccdc8, 0x5590, 0x42dc, { 0x9a, 0x7b, 0xb5, 0xa6, 0xb5, 0xb3, 0xb6, 0x3b } };
static const GUID ELS_GUID_TRANSLITERATION_MALAYALAM_TO_LATIN = { 0xd8b983b1, 0xf8bf, 0x4a2b, { 0xbc, 0xd5, 0x5b, 0x5e, 0xa2, 0x06, 0x13, 0xe1 } };
static const GUID ELS_GUID_TRANSLITERATION_DEVANAGARI_TO_LATIN = { 0xc4a4dcfe, 0x2661, 0x4d02, { 0x98, 0x35, 0xf4, 0x81, 0x87, 0x10, 0x98, 0x03 } };
static const GUID ELS_GUID_TRANSLITERATION_CYRILLIC_TO_LATIN = { 0x3dd12a98, 0x5afd, 0x4903, { 0xa1, 0x3f, 0xe1, 0x7e, 0x6c, 0x0b, 0xfe, 0x01 } };
static const GUID ELS_GUID_TRANSLITERATION_BENGALI_TO_LATIN = { 0xf4dfd825, 0x91a4, 0x489f, { 0x85, 0x5e, 0x9a, 0xd9, 0xbe, 0xe5, 0x57, 0x27 } };
static const GUID ELS_GUID_TRANSLITERATION_HANGUL_DECOMPOSITION = { 0x4ba2a721, 0xe43d, 0x41b7, { 0xb3, 0x30, 0x53, 0x6a, 0xe1, 0xe4, 0x88, 0x63 } };

#endif /* __ELS_SRVC__ */
