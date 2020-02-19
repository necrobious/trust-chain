// temporenc date tag, (first three bits)
use core::cmp::{PartialOrd, Ordering};
use core::convert::TryFrom;

const DATE_TAG: u8 = 0b1000_0000;

#[derive(Debug,Copy,Clone,Eq)]
pub struct Year(pub u16);

impl Year {
    pub fn is_leap (&self) -> bool {
        ((self.0 % 4 == 0) && (self.0 % 100 != 0)) || (self.0 % 400 == 0)
    }
}

#[derive(PartialOrd, Ord, Debug,Copy,Clone,PartialEq,Eq)]
pub enum Month {
    Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec,
}

#[derive(Debug,Copy,Clone,Eq)]
pub struct Day (pub u8);

#[derive(Debug,Copy,Clone,Eq)]
pub struct Date {
    year: Year,
    month: Month,
    day: Day,
}

impl Ord for Year {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for Year {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Year {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl TryFrom<i32> for Year {
    type Error = DateError;
    fn try_from (value: i32) -> Result<Year, Self::Error> {
        if value < 0 || value > 4094 {
            return Err(DateError::InvalidYear)
        }
        u16::try_from(value).map(Year).map_err(|_| DateError::InvalidYear)
    }
}

impl TryFrom<u32> for Month {
    type Error = DateError;
    fn try_from (value: u32) -> Result<Month, Self::Error> {
        use Month::*;
        if value < 1 || value > 12 {
            return Err(DateError::InvalidMonth)
        }
        Ok(match value {
            1 => Jan, 2 => Feb, 3 => Mar,  4 => Apr,  5 => May,  6 => Jun,
            7 => Jul, 8 => Aug, 9 => Sep, 10 => Oct, 11 => Nov, 12 => Dec,
            _ => return Err(DateError::InvalidMonth)
        })
    }
}


impl Ord for Day {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for Day {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Day {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl TryFrom<u32> for Day {
    type Error = DateError;
    fn try_from (value: u32) -> Result<Day, Self::Error> {
        if value < 1 || value > 31 {
            return Err(DateError::InvalidDay)
        }
        u8::try_from(value).map(Day).map_err(|_| DateError::InvalidDay)
    }
}


impl Ord for Date {
    fn cmp(&self, other: &Self) -> Ordering {
        let cmp = self.year.cmp(&other.year);
        if cmp != Ordering::Equal { return cmp }

        let cmp = self.month.cmp(&other.month);
        if cmp != Ordering::Equal { return cmp }

        let cmp = self.day.cmp(&other.day);
        if cmp != Ordering::Equal { return cmp }

        Ordering::Equal
    }
}

impl PartialEq for Date {
    fn eq(&self, other: &Self) -> bool {
        self.year  == other.year  &&
        self.month == other.month &&
        self.day   == other.day
    }
}


impl PartialOrd for Date {
    fn partial_cmp(&self, other: &Date) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug,Copy,Clone,PartialEq)]
pub enum DateError {
    InvalidDate,
    InvalidDay,
    InvalidMonth,
    InvalidYear, // Year value but be between 0 and 4094, both inclusive.
}

impl Date {
    pub fn new (year:Year, month:Month, day:Day) -> Result<Date, DateError> {
        if year.0 > 4094 { return Err(DateError::InvalidYear) }

        let max = match month {
            Month::Feb if year.is_leap() => 29,
            Month::Feb => 28,
            Month::Apr |
            Month::Jun |
            Month::Sep |
            Month::Nov => 30,
            _          => 31
        };
        if day.0 < 1 || day.0 > max { return Err(DateError::InvalidDay) }

        Ok( Date {year,month,day} )
    }

    pub fn as_bytes (&self) -> [u8;3] {
        use Month::*;
        // temporenc date-only encoding
        let year  : u16 = self.year.0;
        let day   : u8  = self.day.0 - 1;
        let month : u8  = match self.month {
            Jan => 0, Feb => 1, Mar => 2, Apr =>  3, May =>  4, Jun =>  5,
            Jul => 6, Aug => 7, Sep => 8, Oct =>  9, Nov => 10, Dec => 11,
        };

        [
            DATE_TAG | ((year >> 7) as u8),
            ((year << 1) as u8) | (month >> 3),
            (month << 5) | day
        ]
    }

    pub fn from_bytes (bytes: &[u8]) -> Result<Date,DateError> {
        if bytes.len() < 3 { return Err(DateError::InvalidDate) }
        use Month::*;
        if bytes[0] & 0b1110_0000 != DATE_TAG {
            return Err(DateError::InvalidDate);
        }

        let mut year = ((bytes[0] & 0x1F) as u16) << 7;
        year |= (bytes[1] as u16) >> 1;

        let mut month = (bytes[1] & 0x01) << 3;
        month |= (bytes[2] & 0xE0) >> 5;

        let day = bytes[2] & 0x1F;

        let month = match month {
            0 => Jan, 1 => Feb, 2 => Mar, 3 => Apr,  4 => May,  5 => Jun,
            6 => Jul, 7 => Aug, 8 => Sep, 9 => Oct, 10 => Nov, 11 => Dec,
            _ => return Err(DateError::InvalidDate)
        };

        Date::new(Year(year), month, Day(day + 1))
    }

    // true if self is before other,
    // false if self is equal to or later than other
    pub fn is_before(&self, other: &Date) -> bool {self < other}

    // true if self is after other,
    // false if self is equal to or before than other
    pub fn is_after(&self, other: &Date) -> bool {self > other}

    // true if self is within or equal to before and after, before and after inclusive.
    pub fn is_within(&self, before: &Date, after: &Date) -> bool {
        self <= after && self >= before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_and_eq_should_work () {
        assert_eq!(
            Date::new(Year(2000), Month::Jan, Day(31)),
            Date::new(Year(2000), Month::Jan, Day(31))
        );

        assert_ne!(
            Date::new(Year(2000), Month::Jan, Day(30)),
            Date::new(Year(2000), Month::Jan, Day(31))
        );

        assert_eq!(
            Date::new(Year(2000), Month::Jan, Day(30)).unwrap().lt(
                &Date::new(Year(2000), Month::Jan, Day(31)).unwrap()
            ), true
        );

        assert_eq!(
            Date::new(Year(2000), Month::Jan, Day(30)).unwrap().gt(
                &Date::new(Year(2000), Month::Jan, Day(31)).unwrap()
            ), false
        );

        assert_eq!(
            Date::new(Year(2000), Month::Jan, Day(30)).unwrap().eq(
                &Date::new(Year(2000), Month::Jan, Day(31)).unwrap()
            ), false
        );
    }

    #[test]
    fn before_should_work() {
        assert_eq!(
            Date::new(Year(2000), Month::Jan, Day(30)).unwrap().is_before(
                &Date::new(Year(2000), Month::Jan, Day(31)).unwrap()
            ), true
        );
        assert_eq!(
            Date::new(Year(2000), Month::Jan, Day(31)).unwrap().is_before(
                &Date::new(Year(2000), Month::Jan, Day(30)).unwrap()
            ), false
        );
    }

    #[test]
    fn after_should_work() {
        assert_eq!(
            Date::new(Year(2000), Month::Jan, Day(30)).unwrap().is_after(
                &Date::new(Year(2000), Month::Jan, Day(31)).unwrap()
            ), false
        );
        assert_eq!(
            Date::new(Year(2000), Month::Jan, Day(31)).unwrap().is_after(
                &Date::new(Year(2000), Month::Jan, Day(30)).unwrap()
            ), true
        );
    }

    #[test]
    fn within_should_work() {
        let before = Date::new(Year(2000), Month::Jan, Day(29)).unwrap();
        let after  = Date::new(Year(2000), Month::Jan, Day(31)).unwrap();
        let target = Date::new(Year(2000), Month::Jan, Day(30)).unwrap();
        assert_eq!(target.is_within(&before,&after), true);
        assert_eq!(before.is_within(&target,&after), false);
        assert_eq!(after.is_within(&before,&target), false);
    }

    #[test]
    fn leap_year_days () {
        let leap_years = [
            1904, 1908, 1912, 1916, 1920, 1924, 1928, 1932, 1936, 1940,
            1944, 1948, 1952, 1956, 1960, 1964, 1968, 1972, 1976, 1980,
            1984, 1988, 1992, 1996, 2000, 2004, 2008, 2012, 2016, 2020
        ];

        for leap_year in leap_years.iter() {
            let leap_day = Date::new(Year(*leap_year), Month::Feb, Day(29));
            assert!(leap_day.is_ok());
            let leap_day = Date::new(Year(*leap_year+1), Month::Feb, Day(29));
            assert!(leap_day.is_err());
        }
    }

    #[test]
    fn date_should_encode_to_temporenc_format () {
        let date = Date::new(Year(1983), Month::Jan, Day(15));
        assert!(date.is_ok());
        let date = date.unwrap();
        let enc = date.as_bytes();
        assert_eq!(enc, [0b1000_1111,0b0111_1110,0b0000_1110]);

        let date = Date::new(Year(2014), Month::Oct, Day(23));
        assert!(date.is_ok());
        let date = date.unwrap();
        let enc = date.as_bytes();
        assert_eq!(enc, [0b1000_1111,0b1011_1101,0b0011_0110]);

        let date = Date::new(Year(2005), Month::Dec, Day(18));
        assert!(date.is_ok());
        let date = date.unwrap();
        let enc = date.as_bytes();
        assert_eq!(enc, [0b1000_1111,0b1010_1011,0b0111_0001]);

        let date = Date::new(Year(1978), Month::Dec, Day(25));
        assert!(date.is_ok());
        let date = date.unwrap();
        let enc = date.as_bytes();
        assert_eq!(enc, [0b1000_1111,0b0111_0101,0b0111_1000]);

        let date = Date::new(Year(1975), Month::Oct, Day(10));
        assert!(date.is_ok());
        let date = date.unwrap();
        let enc = date.as_bytes();
        assert_eq!(enc, [0b1000_1111,0b0110_1111,0b0010_1001]);
    }

    #[test]
    fn temporenc_format_encoded_date_should_decode () {
        let expected = Date::new(Year(1983), Month::Jan, Day(15));
        assert!(expected.is_ok());
        let expected = expected.unwrap();
        let encoded  = Date::from_bytes(&[0b1000_1111,0b0111_1110,0b0000_1110]);
        assert!(encoded.is_ok());
        let encoded = encoded.unwrap();
        assert_eq!(encoded, expected);

        let expected = Date::new(Year(2014), Month::Oct, Day(23));
        assert!(expected.is_ok());
        let expected = expected.unwrap();
        let encoded  = Date::from_bytes(&[0b1000_1111,0b1011_1101,0b0011_0110]);
        assert!(encoded.is_ok());
        let encoded = encoded.unwrap();
        assert_eq!(encoded, expected);

        let expected = Date::new(Year(2005), Month::Dec, Day(18));
        assert!(expected.is_ok());
        let expected = expected.unwrap();
        let encoded  = Date::from_bytes(&[0b1000_1111,0b1010_1011,0b0111_0001]);
        assert!(encoded.is_ok());
        let encoded = encoded.unwrap();
        assert_eq!(encoded, expected);

        let expected = Date::new(Year(1978), Month::Dec, Day(25));
        assert!(expected.is_ok());
        let expected = expected.unwrap();
        let encoded  = Date::from_bytes(&[0b1000_1111,0b0111_0101,0b0111_1000]);
        assert!(encoded.is_ok());
        let encoded = encoded.unwrap();
        assert_eq!(encoded, expected);

        let expected = Date::new(Year(1975), Month::Oct, Day(10));
        assert!(expected.is_ok());
        let expected = expected.unwrap();
        let encoded  = Date::from_bytes(&[0b1000_1111,0b0110_1111,0b0010_1001]);
        assert!(encoded.is_ok());
        let encoded = encoded.unwrap();
        assert_eq!(encoded, expected);
    }
}
