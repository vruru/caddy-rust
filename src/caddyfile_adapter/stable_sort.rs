// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Port of Go's stable_func, symMerge_func, rotate_func to Rust.

pub(super) fn stable_sort<T, F>(values: &mut [T], mut less: F)
where
    F: FnMut(&T, &T) -> bool,
{
    let n = values.len();
    if n <= 1 {
        return;
    }

    const BLOCK_SIZE: usize = 20;

    // Insertion sort initial blocks
    let mut a = 0;
    let mut b = BLOCK_SIZE;
    while b <= n {
        insertion_sort(values, a, b, &mut less);
        a = b;
        b += BLOCK_SIZE;
    }
    insertion_sort(values, a, n, &mut less);

    // Merge passes
    let mut block_size = BLOCK_SIZE;
    while block_size < n {
        a = 0;
        b = 2 * block_size;
        while b <= n {
            sym_merge(values, a, a + block_size, b, &mut less);
            a = b;
            b += 2 * block_size;
        }
        let m = a + block_size;
        if m < n {
            sym_merge(values, a, m, n, &mut less);
        }
        block_size *= 2;
    }
}

fn insertion_sort<T, F>(values: &mut [T], a: usize, b: usize, less: &mut F)
where
    F: FnMut(&T, &T) -> bool,
{
    for i in (a + 1)..b {
        let mut j = i;
        while j > a && less(&values[j], &values[j - 1]) {
            values.swap(j, j - 1);
            j -= 1;
        }
    }
}

fn sym_merge<T, F>(values: &mut [T], a: usize, m: usize, b: usize, less: &mut F)
where
    F: FnMut(&T, &T) -> bool,
{
    debug_assert!(a < m && m < b, "non-degenerate arguments required");

    // Case: left part has one element
    if m - a == 1 {
        // Binary search for first index i in [m, b) where values[i] >= values[a]
        // i.e., !less(&values[i], &values[a])
        let mut i = m;
        let mut j = b;
        while i < j {
            let h = (i + j) >> 1;
            if less(&values[h], &values[a]) {
                i = h + 1;
            } else {
                j = h;
            }
        }
        // Rotate values[a..i] left by 1
        for k in a..(i - 1) {
            values.swap(k, k + 1);
        }
        return;
    }

    // Case: right part has one element
    if b - m == 1 {
        // Binary search for first index i in [a, m) where values[i] > values[m]
        // i.e., less(&values[m], &values[i])
        let mut i = a;
        let mut j = m;
        while i < j {
            let h = (i + j) >> 1;
            if !less(&values[m], &values[h]) {
                i = h + 1;
            } else {
                j = h;
            }
        }
        // Rotate values[i..=m] right by 1
        for k in ((i + 1)..=m).rev() {
            values.swap(k, k - 1);
        }
        return;
    }

    let mid = (a + b) >> 1;
    let n = mid + m;
    let mut start;
    let mut r;
    if m > mid {
        start = n - b;
        r = mid;
    } else {
        start = a;
        r = m;
    }
    let p = n - 1;

    while start < r {
        let c = (start + r) >> 1;
        if !less(&values[p - c], &values[c]) {
            start = c + 1;
        } else {
            r = c;
        }
    }

    let end = n - start;
    if start < m && m < end {
        rotate(values, start, m, end);
    }
    if a < start && start < mid {
        sym_merge(values, a, start, mid, less);
    }
    if mid < end && end < b {
        sym_merge(values, mid, end, b, less);
    }
}

fn rotate<T>(values: &mut [T], a: usize, m: usize, b: usize) {
    debug_assert!(a < m && m < b, "non-degenerate arguments required");

    let mut i = m - a;
    let mut j = b - m;

    while i != j {
        if i > j {
            swap_range(values, m - i, m, j);
            i -= j;
        } else {
            swap_range(values, m - i, m + j - i, i);
            j -= i;
        }
    }
    // i == j
    swap_range(values, m - i, m, i);
}

fn swap_range<T>(values: &mut [T], a: usize, b: usize, n: usize) {
    for i in 0..n {
        values.swap(a + i, b + i);
    }
}
