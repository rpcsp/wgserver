use qrcode::{Color, EcLevel, QrCode};

pub fn qrcode_string(text: &str) -> Result<String, qrcode::types::QrError> {
    let code = QrCode::with_error_correction_level(text, EcLevel::L)?;
    let mut qrcode_lines = String::new();

    let width = code.width();
    let border = 2;

    // Include a quiet zone around the QR code.
    let size = width + border * 2;

    for y in (0..size).step_by(2) {
        let mut line = String::new();

        for x in 0..size {
            let upper = if y >= border && y < size - border && x >= border && x < size - border {
                code[(x - border, y - border)]
            } else {
                Color::Light
            };

            let lower =
                if y + 1 >= border && y + 1 < size - border && x >= border && x < size - border {
                    code[(x - border, y + 1 - border)]
                } else {
                    Color::Light
                };

            match (upper, lower) {
                (Color::Dark, Color::Dark) => line.push(' '),
                (Color::Dark, Color::Light) => line.push('▄'),
                (Color::Light, Color::Dark) => line.push('▀'),
                (Color::Light, Color::Light) => line.push('█'),
            }
        }
        qrcode_lines.push_str(&line);
        qrcode_lines.push('\n');
    }

    Ok(qrcode_lines)
}
