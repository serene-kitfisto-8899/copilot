//! Incremental, crash-safe reader for the CLI's append-only JSONL files.
//!
//! Rules (all observed on real files):
//!   * a `\n`-terminated line is consumed, even if blank or NUL padded;
//!   * an unterminated tail is consumed only when it is a complete JSON
//!     document, otherwise it is left for the next pass (the CLI may still be
//!     writing it, or a crash left a NUL-padded stub that is never completed);
//!   * leading/trailing NUL and whitespace bytes are ignored.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use serde::de::IgnoredAny;

use crate::db::sha256_hex;

/// How much of the start of a file is hashed to notice that it was replaced.
pub const HEAD_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Byte offset where the raw line starts (before any NUL padding).
    pub offset: u64,
    /// The line without padding or the line terminator.
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct Chunk {
    pub lines: Vec<Line>,
    /// First byte not consumed: persist this as the resume offset.
    pub end_offset: u64,
    /// True once the end of the file (or an unconsumable tail) was reached.
    pub done: bool,
}

pub struct LineReader {
    file: BufReader<File>,
    pos: u64,
}

fn is_padding(b: u8) -> bool {
    matches!(b, 0 | b' ' | b'\t' | b'\r' | b'\n')
}

fn trim_padding(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if !is_padding(*first) {
            break;
        }
        bytes = rest;
    }
    while let [rest @ .., last] = bytes {
        if !is_padding(*last) {
            break;
        }
        bytes = rest;
    }
    bytes
}

impl LineReader {
    pub fn open(path: &Path, start: u64) -> io::Result<Self> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(start))?;
        Ok(Self {
            file: BufReader::with_capacity(1 << 20, file),
            pos: start,
        })
    }

    /// Reads until `max_lines` lines or `max_bytes` bytes were collected, or
    /// until nothing more can be consumed.
    pub fn next_chunk(&mut self, max_lines: usize, max_bytes: usize) -> io::Result<Chunk> {
        let mut lines = Vec::new();
        let mut bytes = 0usize;
        let mut buf = Vec::new();
        let mut done = false;
        while lines.len() < max_lines && bytes < max_bytes {
            buf.clear();
            let n = self.file.read_until(b'\n', &mut buf)?;
            if n == 0 {
                done = true;
                break;
            }
            let start = self.pos;
            let trimmed = trim_padding(&buf);
            if buf.last() == Some(&b'\n') {
                self.pos += n as u64;
                if !trimmed.is_empty() {
                    bytes += trimmed.len();
                    lines.push(Line {
                        offset: start,
                        bytes: trimmed.to_vec(),
                    });
                }
            } else {
                if trimmed.first() == Some(&b'{')
                    && serde_json::from_slice::<IgnoredAny>(trimmed).is_ok()
                {
                    self.pos += n as u64;
                    lines.push(Line {
                        offset: start,
                        bytes: trimmed.to_vec(),
                    });
                }
                done = true;
                break;
            }
        }
        Ok(Chunk {
            lines,
            end_offset: self.pos,
            done,
        })
    }
}

/// SHA-256 of the first `min(offset, HEAD_BYTES)` bytes of the file, or `None`
/// when the file is shorter than that (so it cannot be the file that was read).
pub fn head_sha(path: &Path, offset: u64) -> io::Result<Option<String>> {
    let want = usize::try_from(offset.min(HEAD_BYTES)).unwrap_or(0);
    let mut buf = vec![0u8; want];
    let mut file = File::open(path)?;
    match file.read_exact(&mut buf) {
        Ok(()) => Ok(Some(sha256_hex(&buf))),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    fn all(path: &Path, start: u64) -> (Vec<String>, u64) {
        let mut reader = LineReader::open(path, start).unwrap();
        let mut out = Vec::new();
        loop {
            let chunk = reader.next_chunk(2, 1 << 20).unwrap();
            out.extend(
                chunk
                    .lines
                    .iter()
                    .map(|l| String::from_utf8(l.bytes.clone()).unwrap()),
            );
            if chunk.done {
                return (out, chunk.end_offset);
            }
        }
    }

    #[test]
    fn reads_terminated_lines_and_reports_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        write(&p, b"{\"a\":1}\n{\"b\":2}\n");
        let mut reader = LineReader::open(&p, 0).unwrap();
        let chunk = reader.next_chunk(10, 1 << 20).unwrap();
        assert_eq!(chunk.lines.len(), 2);
        assert_eq!(chunk.lines[0].offset, 0);
        assert_eq!(chunk.lines[1].offset, 8);
        assert_eq!(chunk.end_offset, 16);
        assert!(chunk.done);
    }

    #[test]
    fn partial_tail_waits_until_the_line_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        write(&p, b"{\"a\":1}\n{\"b\":");
        let (lines, end) = all(&p, 0);
        assert_eq!(lines, vec![r#"{"a":1}"#]);
        assert_eq!(end, 8);

        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"2}\n").unwrap();
        let (lines, end) = all(&p, 8);
        assert_eq!(lines, vec![r#"{"b":2}"#]);
        assert_eq!(end, 16);
    }

    #[test]
    fn unterminated_but_complete_json_is_consumed_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        write(&p, b"{\"a\":1}\n{\"b\":2}");
        let (lines, end) = all(&p, 0);
        assert_eq!(lines.len(), 2);
        assert_eq!(end, 15);
        // The terminator arriving later is a blank line, not a duplicate.
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"\n{\"c\":3}\n").unwrap();
        let (lines, _) = all(&p, 15);
        assert_eq!(lines, vec![r#"{"c":3}"#]);
    }

    #[test]
    fn nul_padded_tail_is_never_consumed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        let mut content = b"{\"a\":1}\n".to_vec();
        content.extend(std::iter::repeat_n(0u8, 64));
        write(&p, &content);
        let (lines, end) = all(&p, 0);
        assert_eq!(lines.len(), 1);
        assert_eq!(end, 8);
        // Same answer on every later pass.
        let (lines, end) = all(&p, 8);
        assert!(lines.is_empty());
        assert_eq!(end, 8);
    }

    #[test]
    fn padding_around_terminated_lines_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        write(&p, b"\0\0{\"a\":1}\r\n\0\0\0\n   \n{\"b\":2}\n");
        let (lines, end) = all(&p, 0);
        assert_eq!(lines, vec![r#"{"a":1}"#, r#"{"b":2}"#]);
        assert_eq!(end, 27);
    }

    #[test]
    fn head_sha_detects_a_replaced_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        write(&p, b"{\"a\":1}\n{\"b\":2}\n");
        let first = head_sha(&p, 16).unwrap().unwrap();
        // Appending keeps the hash of the consumed prefix.
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"c\":3}\n").unwrap();
        assert_eq!(head_sha(&p, 16).unwrap().unwrap(), first);
        // A different file of the same or larger size does not.
        write(&p, b"{\"z\":9}\n{\"y\":8}\n{\"x\":7}\n");
        assert_ne!(head_sha(&p, 16).unwrap().unwrap(), first);
        // A shorter file cannot be the one that was read.
        write(&p, b"{}\n");
        assert_eq!(head_sha(&p, 16).unwrap(), None);
    }
}
