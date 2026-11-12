// Copyright 2009 The Go Authors. All rights reserved.
// Behavioral adaptation of Go 1.27.3 runtime/slice.go and runtime/msize.go.
// Go's BSD license applies to the derived capacity calculation and size table.

/// Capacity after appending to a 64-bit Go slice. `new_len` includes all
/// elements in this append; an existing capacity is preserved when sufficient.
/// This models capacity only, and never allocates or changes slice contents.
pub fn go_slice_capacity(
    old_cap: usize,
    new_len: usize,
    element_size: usize,
    has_pointers: bool,
) -> Option<usize> {
    if usize::BITS != 64 || new_len > isize::MAX as usize {
        return None;
    }
    if new_len <= old_cap {
        return Some(old_cap);
    }
    if element_size == 0 {
        return Some(new_len);
    }
    let double = old_cap.checked_mul(2)?;
    let mut cap = if new_len > double {
        new_len
    } else if old_cap < 256 {
        double
    } else {
        let mut cap = old_cap;
        while cap < new_len {
            cap = cap.checked_add(cap.checked_add(768)? >> 2)?;
        }
        cap
    };
    let bytes = cap.checked_mul(element_size)?;
    let rounded = if bytes <= 32768 - 8 {
        let header = usize::from(has_pointers && bytes > 512) * 8;
        let requested = bytes.checked_add(header)?;
        const CLASSES: [usize; 68] = [
            0, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
            288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024, 1152, 1280,
            1408, 1536, 1792, 2048, 2304, 2688, 3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528,
            6784, 6912, 8192, 9472, 9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072,
            20480, 21760, 24576, 27264, 28672, 32768,
        ];
        CLASSES
            .iter()
            .copied()
            .find(|&size| size >= requested)?
            .checked_sub(header)?
    } else {
        bytes.checked_add(8191)? & !8191
    };
    cap = rounded / element_size;
    if cap < new_len || cap.checked_mul(element_size)? > isize::MAX as usize {
        return None;
    }
    Some(cap)
}
