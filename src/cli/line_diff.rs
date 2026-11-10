// Copyright (c) 2016 Aryan Naraghi
// SPDX-License-Identifier: MIT
// Behavioral port of github.com/aryann/difflib ff5ff6dc229b.
use anyhow::{Result, ensure};
fn emit(out: &mut Vec<u8>, prefix: &[u8], line: &[u8], limit: usize) -> Result<()> {
    ensure!(
        out.len()
            .checked_add(prefix.len())
            .and_then(|n| n.checked_add(line.len()))
            .and_then(|n| n.checked_add(1))
            .is_some_and(|n| n <= limit),
        "format diff output limit exceeded"
    );
    out.extend_from_slice(prefix);
    out.extend_from_slice(line);
    out.push(b'\n');
    Ok(())
}
pub(super) fn diff(left: &[u8], right: &[u8], limit: usize) -> Result<Vec<u8>> {
    let lines = left
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        .checked_add(right.iter().filter(|b| **b == b'\n').count())
        .and_then(|n| n.checked_add(2));
    ensure!(
        lines
            .and_then(|n| n.checked_mul(std::mem::size_of::<&[u8]>()))
            .is_some_and(|n| n <= 64 * 1024 * 1024),
        "format diff line budget exceeded"
    );
    let left = left.split(|b| *b == b'\n').collect::<Vec<_>>();
    let right = right.split(|b| *b == b'\n').collect::<Vec<_>>();
    let mut start = 0;
    while start < left.len() && start < right.len() && left[start] == right[start] {
        start += 1;
    }
    let mut end = 0;
    let (mut a, mut b) = (left.len().saturating_sub(1), right.len().saturating_sub(1));
    while a > start && b > start && left[a] == right[b] {
        end += 1;
        a -= 1;
        b -= 1;
    }
    let l = &left[start..left.len() - end];
    let r = &right[start..right.len() - end];
    let width = r
        .len()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("format diff size overflow"))?;
    let cells = l.len().checked_add(1).and_then(|n| n.checked_mul(width));
    ensure!(
        cells.is_some_and(|n| n <= 16 * 1024 * 1024),
        "format diff work budget exceeded"
    );
    let mut matrix = vec![0u32; cells.unwrap()];
    for i in 1..=l.len() {
        for j in 1..=r.len() {
            matrix[i * width + j] = if l[l.len() - i] == r[r.len() - j] {
                matrix[(i - 1) * width + j - 1] + 1
            } else {
                matrix[(i - 1) * width + j].max(matrix[i * width + j - 1])
            };
        }
    }
    let mut out = Vec::new();
    for line in &left[..start] {
        emit(&mut out, b"  ", line, limit)?;
    }
    let (mut i, mut j) = (l.len(), r.len());
    while i > 0 || j > 0 {
        if i > 0 && matrix[i * width + j] == matrix[(i - 1) * width + j] {
            emit(&mut out, b"- ", l[l.len() - i], limit)?;
            i -= 1;
        } else if j > 0 && matrix[i * width + j] == matrix[i * width + j - 1] {
            emit(&mut out, b"+ ", r[r.len() - j], limit)?;
            j -= 1;
        } else {
            emit(&mut out, b"  ", l[l.len() - i], limit)?;
            i -= 1;
            j -= 1;
        }
    }
    for line in &left[left.len() - end..] {
        emit(&mut out, b"  ", line, limit)?;
    }
    Ok(out)
}
