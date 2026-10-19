//! Fecha y hora en UTC.
//!
//! La conversión de días desde la época al calendario gregoriano es el algoritmo de
//! Howard Hinnant. Está aquí, y no en una dependencia, porque es lo único que hacía
//! falta de una biblioteca de fechas.
//!
//! Todo lo que Rhino guarda va en UTC y en segundos desde la época. Pasar a la hora
//! local es asunto de la capa de presentación, que es la única que sabe en qué huso
//! está el equipo.

use std::time::{SystemTime, UNIX_EPOCH};

/// Fecha y hora UTC descompuesta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utc {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

/// Segundos transcurridos desde el 1 de enero de 1970, en UTC.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Descompone segundos desde la época en el calendario gregoriano, en UTC.
pub fn from_unix(unix: u64) -> Utc {
    let (year, month, day) = days_to_civil((unix / 86_400) as i64);
    let time = unix % 86_400;

    Utc {
        year,
        month,
        day,
        hour: (time / 3600) as u32,
        minute: ((time % 3600) / 60) as u32,
        second: (time % 60) as u32,
    }
}

/// `2026.10.18`: solo la fecha, para nombrar paquetes.
pub fn utc_date(unix: u64) -> String {
    let date = from_unix(unix);

    format!("{:04}.{:02}.{:02}", date.year, date.month, date.day)
}

/// `2026-10-18T21:14:00Z`: fecha y hora completas, RFC 3339.
pub fn utc_rfc3339(unix: u64) -> String {
    let at = from_unix(unix);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        at.year, at.month, at.day, at.hour, at.minute, at.second
    )
}

/// Días desde el 1 de enero de 1970 al año, mes y día del calendario gregoriano.
fn days_to_civil(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;

    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_the_first_of_january_1970() {
        assert_eq!(days_to_civil(0), (1970, 1, 1));
    }

    #[test]
    fn a_leap_day_is_handled() {
        assert_eq!(days_to_civil(19_782), (2024, 2, 29));
    }

    #[test]
    fn a_recent_date_lines_up() {
        assert_eq!(days_to_civil(20_744), (2026, 10, 18));
    }

    #[test]
    fn the_time_of_day_is_split_correctly() {
        // 2026-10-18T21:14:05Z
        let at = from_unix(20_744 * 86_400 + 21 * 3600 + 14 * 60 + 5);

        assert_eq!(
            at,
            Utc {
                year: 2026,
                month: 10,
                day: 18,
                hour: 21,
                minute: 14,
                second: 5
            }
        );
    }

    #[test]
    fn the_date_is_a_date_and_the_timestamp_is_rfc3339() {
        let unix = 20_744 * 86_400 + 21 * 3600 + 14 * 60;

        assert_eq!(utc_date(unix), "2026.10.18");
        assert_eq!(utc_rfc3339(unix), "2026-10-18T21:14:00Z");
        assert_eq!(utc_rfc3339(now_unix()).len(), 20);
    }
}
