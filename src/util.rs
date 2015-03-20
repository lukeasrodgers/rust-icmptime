extern crate time;

pub fn seconds_after_utc() -> u32 {
    let t = time::now_utc();
    let s: i32 = t.tm_hour * 3600 + t.tm_min * 60 + t.tm_sec;
    s as u32
}

pub fn ones_complement_sum(sl: &[u16]) -> u16 {
    let sum = sl.iter().fold(0u32, |sum, x| sum + (*x as u32));
    65535 - (sum as u16) - (sum >> 16) as u16
}

mod tests {
    use super::ones_complement_sum;

    // examples for ones complement sum taken from web
    #[test]
    fn test_ones_complement_sum() {
        let mut vec: Vec<u16> = vec![];
        vec.push(0x4500);
        vec.push(0x003c);
        vec.push(0x1c46);
        vec.push(0x4000);
        vec.push(0x4006);
        vec.push(0x0000);
        vec.push(0xac10);
        vec.push(0x0a63);
        vec.push(0xac10);
        vec.push(0x0a0c);
        let r = vec.as_slice();
        assert_eq!(ones_complement_sum(r), 0xB1E6);
    }

    #[test]
    fn another_test_ones_complement_sum() {
        let mut vec: Vec<u16> = vec![];
        vec.push(0x0800);
        vec.push(0x0000);
        vec.push(0x0001);
        vec.push(0x1008);
        vec.push(0x6162);
        vec.push(0x6364);
        vec.push(0x6566);
        vec.push(0x6768);
        vec.push(0x696a);
        vec.push(0x6b6c);
        vec.push(0x6d6e);
        vec.push(0x6f70);
        vec.push(0x7172);
        vec.push(0x7374);
        vec.push(0x7576);
        vec.push(0x7761);
        vec.push(0x6263);
        vec.push(0x6465);
        vec.push(0x6667);
        vec.push(0x6869);
        let r = vec.as_slice();
        assert_eq!(ones_complement_sum(r), 15699);
    }
}
