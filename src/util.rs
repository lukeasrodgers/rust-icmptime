extern crate time;

pub fn msecs_after_utc() -> u32 {
    let t = time::now_utc();
    let s: i32 = (t.tm_hour * 3600 + t.tm_min * 60 + t.tm_sec) * 1000;
    s as u32
}

pub fn ones_complement_sum(sl: &[u8]) -> u16 {
    let len = 20;
    let mut sum = 0u32;
    let mut i = 0;
    while i < len {
        let word = (sl[i] as u32) << 8 | sl[i + 1] as u32;
        sum = sum + word;
        i = i + 2;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    return !sum as u16;
}
