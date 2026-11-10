// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Behavioral port of Go net/http/sniff.go

use std::convert::TryInto;

const SNIFF_LEN: usize = 512;

pub(super) fn detect_content_type(data: &[u8]) -> &'static str {
    let data = if data.len() > SNIFF_LEN {
        &data[..SNIFF_LEN]
    } else {
        data
    };

    let first_non_ws = first_non_ws_index(data);

    for sig in sniff_signatures() {
        if let Some(ct) = sig.match_signature(data, first_non_ws) {
            return ct;
        }
    }

    "application/octet-stream"
}

fn is_ws(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn is_tt(b: u8) -> bool {
    matches!(b, b' ' | b'>')
}

fn first_non_ws_index(data: &[u8]) -> usize {
    let mut i = 0;
    while i < data.len() && is_ws(data[i]) {
        i += 1;
    }
    i
}

trait SniffSig: Sync + Send {
    fn match_signature(&self, data: &[u8], first_non_ws: usize) -> Option<&'static str>;
}

struct ExactSig {
    sig: &'static [u8],
    ct: &'static str,
}

impl SniffSig for ExactSig {
    fn match_signature(&self, data: &[u8], _first_non_ws: usize) -> Option<&'static str> {
        if data.len() >= self.sig.len() && &data[..self.sig.len()] == self.sig {
            Some(self.ct)
        } else {
            None
        }
    }
}

struct MaskedSig {
    mask: &'static [u8],
    pat: &'static [u8],
    skip_ws: bool,
    ct: &'static str,
}

impl SniffSig for MaskedSig {
    fn match_signature(&self, data: &[u8], first_non_ws: usize) -> Option<&'static str> {
        let data = if self.skip_ws {
            if first_non_ws >= data.len() {
                return None;
            }
            &data[first_non_ws..]
        } else {
            data
        };

        if self.pat.len() != self.mask.len() {
            return None;
        }
        if data.len() < self.pat.len() {
            return None;
        }
        for (i, pb) in self.pat.iter().enumerate() {
            let masked_data = data[i] & self.mask[i];
            if masked_data != *pb {
                return None;
            }
        }
        Some(self.ct)
    }
}

struct HtmlSig {
    prefix: &'static [u8],
}

impl SniffSig for HtmlSig {
    fn match_signature(&self, data: &[u8], first_non_ws: usize) -> Option<&'static str> {
        let data = &data[first_non_ws..];
        if data.len() < self.prefix.len() + 1 {
            return None;
        }
        for (i, b) in self.prefix.iter().enumerate() {
            let db = data[i];
            let mut db = db;
            if *b >= b'A' && *b <= b'Z' {
                db &= 0xDF;
            }
            if *b != db {
                return None;
            }
        }
        if !is_tt(data[self.prefix.len()]) {
            return None;
        }
        Some("text/html; charset=utf-8")
    }
}

struct Mp4Sig {}

impl SniffSig for Mp4Sig {
    fn match_signature(&self, data: &[u8], _first_non_ws: usize) -> Option<&'static str> {
        if data.len() < 12 {
            return None;
        }
        let box_size = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
        if data.len() < box_size || !box_size.is_multiple_of(4) {
            return None;
        }
        let mp4_type = b"ftyp";
        if data[4..8] != *mp4_type {
            return None;
        }
        let mut st = 8;
        while st < box_size {
            if st + 3 > data.len() {
                return None;
            }
            if st == 12 {
                st += 4;
                continue;
            }
            let mp4 = b"mp4";
            if data[st..st + 3] == *mp4 {
                return Some("video/mp4");
            }
            st += 4;
        }
        None
    }
}

struct TextSig {}

impl SniffSig for TextSig {
    fn match_signature(&self, data: &[u8], first_non_ws: usize) -> Option<&'static str> {
        for &b in &data[first_non_ws..] {
            match b {
                0x00..=0x08 | 0x0B | 0x0E..=0x1A | 0x1C..=0x1F => {
                    return None;
                }
                _ => {}
            }
        }
        Some("text/plain; charset=utf-8")
    }
}

fn sniff_signatures() -> &'static [Box<dyn SniffSig>] {
    static SIGNATURES: std::sync::LazyLock<Vec<Box<dyn SniffSig>>> = std::sync::LazyLock::new(
        || {
            vec![
        Box::new(HtmlSig { prefix: b"<!DOCTYPE HTML" }),
        Box::new(HtmlSig { prefix: b"<HTML" }),
        Box::new(HtmlSig { prefix: b"<HEAD" }),
        Box::new(HtmlSig { prefix: b"<SCRIPT" }),
        Box::new(HtmlSig { prefix: b"<IFRAME" }),
        Box::new(HtmlSig { prefix: b"<H1" }),
        Box::new(HtmlSig { prefix: b"<DIV" }),
        Box::new(HtmlSig { prefix: b"<FONT" }),
        Box::new(HtmlSig { prefix: b"<TABLE" }),
        Box::new(HtmlSig { prefix: b"<A" }),
        Box::new(HtmlSig { prefix: b"<STYLE" }),
        Box::new(HtmlSig { prefix: b"<TITLE" }),
        Box::new(HtmlSig { prefix: b"<B" }),
        Box::new(HtmlSig { prefix: b"<BODY" }),
        Box::new(HtmlSig { prefix: b"<BR" }),
        Box::new(HtmlSig { prefix: b"<P" }),
        Box::new(HtmlSig { prefix: b"<!--" }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\xFF\xFF\xFF",
            pat: b"<?xml",
            skip_ws: true,
            ct: "text/xml; charset=utf-8",
        }),
        Box::new(ExactSig {
            sig: b"%PDF-",
            ct: "application/pdf",
        }),
        Box::new(ExactSig {
            sig: b"%!PS-Adobe-",
            ct: "application/postscript",
        }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\x00\x00",
            pat: b"\xFE\xFF\x00\x00",
            skip_ws: false,
            ct: "text/plain; charset=utf-16be",
        }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\x00\x00",
            pat: b"\xFF\xFE\x00\x00",
            skip_ws: false,
            ct: "text/plain; charset=utf-16le",
        }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\xFF\x00",
            pat: b"\xEF\xBB\xBF\x00",
            skip_ws: false,
            ct: "text/plain; charset=utf-8",
        }),
        Box::new(ExactSig {
            sig: b"\x00\x00\x01\x00",
            ct: "image/x-icon",
        }),
        Box::new(ExactSig {
            sig: b"\x00\x00\x02\x00",
            ct: "image/x-icon",
        }),
        Box::new(ExactSig {
            sig: b"BM",
            ct: "image/bmp",
        }),
        Box::new(ExactSig {
            sig: b"GIF87a",
            ct: "image/gif",
        }),
        Box::new(ExactSig {
            sig: b"GIF89a",
            ct: "image/gif",
        }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
            pat: b"RIFF\x00\x00\x00\x00WEBPVP",
            skip_ws: false,
            ct: "image/webp",
        }),
        Box::new(ExactSig {
            sig: b"\x89PNG\x0D\x0A\x1A\x0A",
            ct: "image/png",
        }),
        Box::new(ExactSig {
            sig: b"\xFF\xD8\xFF",
            ct: "image/jpeg",
        }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
            pat: b"FORM\x00\x00\x00\x00AIFF",
            skip_ws: false,
            ct: "audio/aiff",
        }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\xFF",
            pat: b"ID3",
            skip_ws: false,
            ct: "audio/mpeg",
        }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\xFF\xFF\xFF",
            pat: b"OggS\x00",
            skip_ws: false,
            ct: "application/ogg",
        }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
            pat: b"MThd\x00\x00\x00\x06",
            skip_ws: false,
            ct: "audio/midi",
        }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
            pat: b"RIFF\x00\x00\x00\x00AVI ",
            skip_ws: false,
            ct: "video/avi",
        }),
        Box::new(MaskedSig {
            mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
            pat: b"RIFF\x00\x00\x00\x00WAVE",
            skip_ws: false,
            ct: "audio/wave",
        }),
        Box::new(Mp4Sig {}),
        Box::new(ExactSig {
            sig: b"\x1A\x45\xDF\xA3",
            ct: "video/webm",
        }),
        Box::new(MaskedSig {
            pat: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP",
            mask: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
            skip_ws: false,
            ct: "application/vnd.ms-fontobject",
        }),
        Box::new(ExactSig {
            sig: b"\x00\x01\x00\x00",
            ct: "font/ttf",
        }),
        Box::new(ExactSig {
            sig: b"OTTO",
            ct: "font/otf",
        }),
        Box::new(ExactSig {
            sig: b"ttcf",
            ct: "font/collection",
        }),
        Box::new(ExactSig {
            sig: b"wOFF",
            ct: "font/woff",
        }),
        Box::new(ExactSig {
            sig: b"wOF2",
            ct: "font/woff2",
        }),
        Box::new(ExactSig {
            sig: b"\x1F\x8B\x08",
            ct: "application/x-gzip",
        }),
        Box::new(ExactSig {
            sig: b"PK\x03\x04",
            ct: "application/zip",
        }),
        Box::new(ExactSig {
            sig: b"Rar!\x1A\x07\x00",
            ct: "application/x-rar-compressed",
        }),
        Box::new(ExactSig {
            sig: b"Rar!\x1A\x07\x01\x00",
            ct: "application/x-rar-compressed",
        }),
        Box::new(ExactSig {
            sig: b"\x00\x61\x73\x6D",
            ct: "application/wasm",
        }),
        Box::new(TextSig {}),
    ]
        },
    );
    &SIGNATURES
}
