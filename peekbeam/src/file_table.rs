//! Path formatting for the Files panel (FR4).

use peekbeam_common::FILE_PATH_MAX;

pub fn format_path(path: &[u8], path_len: u16) -> String {
    let len = (path_len as usize).min(path.len());
    let text = String::from_utf8_lossy(&path[..len]).into_owned();
    if path_len as usize >= FILE_PATH_MAX {
        format!("{text}…")
    } else {
        text
    }
}

/// Truncates a long path in the middle (keeping the filename visible) rather
/// than at the end, for narrow table columns.
pub fn truncate_middle(path: &str, max_len: usize) -> String {
    let char_count = path.chars().count();
    if char_count <= max_len || max_len < 5 {
        return path.to_string();
    }
    let keep = max_len - 1;
    let head = keep / 2;
    let tail = keep - head;
    let chars: Vec<char> = path.chars().collect();
    let head_str: String = chars[..head].iter().collect();
    let tail_str: String = chars[char_count - tail..].iter().collect();
    format!("{head_str}…{tail_str}")
}
