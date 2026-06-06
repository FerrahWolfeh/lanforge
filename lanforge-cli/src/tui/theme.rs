use ratatui::style::Color;

// Catppuccin Mocha Palette
pub const MOCHA_RED: Color = Color::Rgb(243, 139, 168);
pub const MOCHA_GREEN: Color = Color::Rgb(166, 227, 161);
pub const MOCHA_YELLOW: Color = Color::Rgb(249, 226, 175);
pub const MOCHA_BLUE: Color = Color::Rgb(137, 180, 250);
pub const MOCHA_PINK: Color = Color::Rgb(245, 194, 231);
pub const MOCHA_PEACH: Color = Color::Rgb(250, 179, 135);
pub const MOCHA_TEAL: Color = Color::Rgb(148, 226, 213);
pub const MOCHA_LAVENDER: Color = Color::Rgb(180, 190, 254);
pub const MOCHA_MAUVE: Color = Color::Rgb(203, 166, 247);
pub const MOCHA_SAPPHIRE: Color = Color::Rgb(116, 199, 236);
pub const MOCHA_BASE: Color = Color::Rgb(30, 30, 46);
pub const MOCHA_SURFACE2: Color = Color::Rgb(88, 91, 112);
pub const MOCHA_TEXT: Color = Color::Rgb(205, 214, 244);
pub const MOCHA_SUBTEXT0: Color = Color::Rgb(166, 173, 200);

// Semantic Theme
pub const ONLINE: Color = MOCHA_GREEN;
pub const STALE: Color = MOCHA_YELLOW;
pub const OFFLINE: Color = MOCHA_SURFACE2;

pub const HEADER_BG: Color = MOCHA_BASE;
pub const ACCENT: Color = MOCHA_BLUE;
pub const TAB_ACTIVE: Color = MOCHA_PINK;
pub const BORDER: Color = MOCHA_SURFACE2;
pub const TEXT_DIM: Color = MOCHA_SUBTEXT0;
pub const DYNAMIC: Color = MOCHA_TEXT;

// Entity Colors
pub const KEY: Color = MOCHA_PEACH;
pub const VALUE: Color = MOCHA_TEAL;
pub const MAC: Color = MOCHA_YELLOW;
pub const HOSTNAME: Color = MOCHA_BLUE;
pub const IP: Color = MOCHA_LAVENDER;
