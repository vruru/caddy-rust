// Ported from the fixed Go 1.27.3 sort/zsortfunc.go pdqsort helpers.
//
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Translated pdqsort_func from Go stdlib (sort package) to pure Rust.
// This file contains only the necessary helpers for pdqsort.

// --- Constants and Types ---

const MAX_INSERTION: usize = 12;
const SHORTEST_NINTHER: usize = 50;
const MAX_SWAPS: usize = 4 * 3;
const MAX_STEPS: usize = 5;
const SHORTEST_SHIFTING: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortedHint {
    Unknown = 0,
    Increasing = 1,
    Decreasing = 2,
}

// --- XorShift Helper ---

struct XorShift {
    state: u64,
}

impl XorShift {
    fn new(seed: u64) -> Self {
        // In Go: random := xorshift(length)
        // The constructor is effectively type cast, so state = length.
        XorShift { state: seed }
    }

    fn next(&mut self) -> u64 {
        // Fixed Go 1.27.3 sort.go: <<13, >>7, <<17.
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

fn next_power_of_two(length: usize) -> usize {
    if length == 0 {
        return 1;
    }
    let shift = usize::BITS - length.leading_zeros();
    1usize << shift
}

// --- Sorting Helpers ---

fn insertion_sort_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    b: usize,
    less: &mut F,
) {
    if a >= b {
        return;
    }
    for i in a + 1..b {
        let mut j = i;
        while j > a && less(&data[j], &data[j - 1]) {
            data.swap(j, j - 1);
            j -= 1;
        }
    }
}

fn sift_down_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    lo: usize,
    hi: usize,
    first: usize,
    less: &mut F,
) {
    let mut root = lo;
    loop {
        let mut child = 2 * root + 1;
        if child >= hi {
            break;
        }
        if child + 1 < hi && less(&data[first + child], &data[first + child + 1]) {
            child += 1;
        }
        if !less(&data[first + root], &data[first + child]) {
            return;
        }
        data.swap(first + root, first + child);
        root = child;
    }
}

fn heap_sort_func<T, F: FnMut(&T, &T) -> bool>(data: &mut [T], a: usize, b: usize, less: &mut F) {
    let first = a;
    let lo = 0;
    let hi = b - a;
    if hi == 0 {
        return;
    }

    // Build heap with greatest element at top.
    // i goes from (hi-1)/2 down to 0
    let mut i = (hi - 1) / 2;
    loop {
        sift_down_func(data, i, hi, first, less);
        if i == 0 {
            break;
        }
        i -= 1;
    }

    // Pop elements, largest first, into end of data.
    // i goes from hi-1 down to 0
    let mut i = hi - 1;
    loop {
        data.swap(first, first + i);
        sift_down_func(data, lo, i, first, less);
        if i == 0 {
            break;
        }
        i -= 1;
    }
}

fn break_patterns_func<T>(data: &mut [T], a: usize, b: usize) {
    let length = b - a;
    if length >= 8 {
        let mut random = XorShift::new(length as u64);
        let modulus = next_power_of_two(length);

        // Go: for idx := a + (length/4)*2 - 1; idx <= a+(length/4)*2+1; idx++
        let center = a + (length / 4) * 2;
        let start = center - 1;
        let end = center + 1;

        for idx in start..=end {
            let mut other = (random.next() as usize) & (modulus - 1);
            if other >= length {
                other -= length;
            }
            data.swap(idx, a + other);
        }
    }
}

fn order2_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    b: usize,
    swaps: &mut usize,
    less: &mut F,
) -> (usize, usize) {
    if less(&data[b], &data[a]) {
        *swaps += 1;
        (b, a)
    } else {
        (a, b)
    }
}

fn median_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    b: usize,
    c: usize,
    swaps: &mut usize,
    less: &mut F,
) -> usize {
    let (a, b) = order2_func(data, a, b, swaps, less);
    let (b, _c) = order2_func(data, b, c, swaps, less);
    let (_a, b) = order2_func(data, a, b, swaps, less);
    b
}

fn median_adjacent_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    swaps: &mut usize,
    less: &mut F,
) -> usize {
    // Go: median_func(data, a-1, a, a+1, swaps)
    // In Go, data is the full slice, indices are absolute. a is an index.
    median_func(data, a - 1, a, a + 1, swaps, less)
}

fn choose_pivot_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    b: usize,
    less: &mut F,
) -> (usize, SortedHint) {
    let l = b - a;
    let mut swaps = 0;

    let mut i = a + l / 4;
    let mut j = a + l / 4 * 2;
    let mut k = a + l / 4 * 3;

    if l >= 8 {
        if l >= SHORTEST_NINTHER {
            i = median_adjacent_func(data, i, &mut swaps, less);
            j = median_adjacent_func(data, j, &mut swaps, less);
            k = median_adjacent_func(data, k, &mut swaps, less);
        }
        j = median_func(data, i, j, k, &mut swaps, less);
    }

    match swaps {
        0 => (j, SortedHint::Increasing),
        MAX_SWAPS => (j, SortedHint::Decreasing),
        _ => (j, SortedHint::Unknown),
    }
}

fn partition_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    b: usize,
    pivot: usize,
    less: &mut F,
) -> (usize, bool) {
    data.swap(a, pivot);
    // i and j are inclusive of the elements remaining to be partitioned
    let mut i = a + 1;
    let mut j = b - 1;

    // Less(i, a) compares data[i] < data[a]

    while i <= j && less(&data[i], &data[a]) {
        i += 1;
    }
    while i <= j && !less(&data[j], &data[a]) {
        j -= 1;
    }

    if i > j {
        data.swap(j, a);
        return (j, true);
    }

    data.swap(i, j);
    i += 1;
    j -= 1;

    loop {
        while i <= j && less(&data[i], &data[a]) {
            i += 1;
        }
        while i <= j && !less(&data[j], &data[a]) {
            if j == 0 {
                break;
            }
            j -= 1;
        }
        if i > j {
            break;
        }
        data.swap(i, j);
        i += 1;
        if j == 0 {
            break;
        }
        j -= 1;
    }

    data.swap(j, a);
    (j, false)
}

fn partition_equal_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    b: usize,
    pivot: usize,
    less: &mut F,
) -> usize {
    data.swap(a, pivot);
    let mut i = a + 1;
    let mut j = b - 1;

    loop {
        // Move i to the first element > pivot (Less(pivot, i))
        while i <= j && !less(&data[a], &data[i]) {
            i += 1;
        }
        // Move j to the first element <= pivot (!Less(pivot, j))
        while i <= j && less(&data[a], &data[j]) {
            if j == 0 {
                break;
            }
            j -= 1;
        }

        if i > j {
            break;
        }
        data.swap(i, j);
        i += 1;
        if j == 0 {
            break;
        }
        j -= 1;
    }
    i
}

fn partial_insertion_sort_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    b: usize,
    less: &mut F,
) -> bool {
    if b - a < 2 {
        return true;
    }

    let mut i = a + 1;
    for _step in 0..MAX_STEPS {
        // Find the first out-of-order pair starting from i
        while i < b && !less(&data[i], &data[i - 1]) {
            i += 1;
        }

        if i == b {
            return true;
        }

        if b - a < SHORTEST_SHIFTING {
            return false;
        }

        data.swap(i, i - 1);

        // Shift the smaller one to the left.
        // i - a >= 2
        if i - a >= 2 {
            let mut k = i - 1;
            // k >= 1 in Go context is global index.
            // Go: for j := i - 1; j >= 1; j--
            // Condition inside: if !data.Less(j, j-1) break.
            while k >= 1 && less(&data[k], &data[k - 1]) {
                data.swap(k, k - 1);
                if k == 0 {
                    break;
                }
                k -= 1;
            }
        }

        // Shift the greater one to the right.
        // b - i >= 2
        if b - i >= 2 {
            let mut k = i + 1;
            // Go: for j := i + 1; j < b; j++
            // Condition: if !data.Less(j, j-1) break.
            while k < b && less(&data[k], &data[k - 1]) {
                data.swap(k, k - 1);
                k += 1;
            }
        }
    }
    false
}

fn reverse_range_func<T>(data: &mut [T], a: usize, b: usize) {
    if a >= b {
        return;
    }
    let mut i = a;
    let mut j = b - 1;
    while i < j {
        data.swap(i, j);
        i += 1;
        j -= 1;
    }
}

// --- Main PDQSort Logic ---

fn pdqsort_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    mut a: usize,
    mut b: usize,
    mut limit: usize,
    less: &mut F,
) {
    let mut was_balanced = true;
    let mut was_partitioned = true;

    loop {
        let length = b - a;

        if length <= MAX_INSERTION {
            insertion_sort_func(data, a, b, less);
            return;
        }

        if limit == 0 {
            heap_sort_func(data, a, b, less);
            return;
        }

        if !was_balanced {
            break_patterns_func(data, a, b);
            limit -= 1;
        }

        let (mut pivot, mut hint) = choose_pivot_func(data, a, b, less);

        if hint == SortedHint::Decreasing {
            reverse_range_func(data, a, b);
            // The chosen pivot was pivot-a elements after the start of the array.
            // After reversing it is pivot-a elements before the end of the array.
            pivot = (b - 1) - (pivot - a);
            hint = SortedHint::Increasing;
        }

        // The slice is likely already sorted.
        if was_balanced
            && was_partitioned
            && hint == SortedHint::Increasing
            && partial_insertion_sort_func(data, a, b, less)
        {
            return;
        }

        // Probably the slice contains many duplicate elements, partition the slice into
        // elements equal to and elements greater than the pivot.
        // Go: if a > 0 && !data.Less(a-1, pivot)

        if a > 0 && !less(&data[a - 1], &data[pivot]) {
            let mid = partition_equal_func(data, a, b, pivot, less);
            a = mid;
            continue;
        }

        let (mid, already_partitioned) = partition_func(data, a, b, pivot, less);
        was_partitioned = already_partitioned;

        let left_len = mid - a;
        let right_len = b - mid;
        let balance_threshold = length / 8;

        if left_len < right_len {
            was_balanced = left_len >= balance_threshold;
            pdqsort_func(data, a, mid, limit, less);
            a = mid + 1;
        } else {
            was_balanced = right_len >= balance_threshold;
            pdqsort_func(data, mid + 1, b, limit, less);
            b = mid;
        }
    }
}

// --- Public Interface ---

pub(super) fn sort_by<T, F: FnMut(&T, &T) -> bool>(data: &mut [T], mut less: F) {
    let n = data.len();
    if n < 2 {
        return;
    }

    // limit = bits.Len(uint(length))
    // bits.Len returns the position of the highest set bit + 1.
    // For length=1, bits.Len=1. For length=2, bits.Len=2. For length=3, bits.Len=2.
    // Rust: usize::BITS - length.leading_zeros()
    let limit = (usize::BITS - n.leading_zeros()) as usize;

    pdqsort_func(data, 0, n, limit, &mut less);
}
