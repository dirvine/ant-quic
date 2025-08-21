// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Terminal UI formatting and display helpers for ant-quic
//!
//! Provides colored output, formatting, and visual elements for better UX

use std::net::{IpAddr, SocketAddr};
use tracing::Level;
use tracing_subscriber::fmt::{FormatFields, format::Writer};
use unicode_width::UnicodeWidthStr;
// use four_word_networking::FourWordAdaptiveEncoder; // TODO: Add this dependency or implement locally

/// ANSI color codes for terminal output
pub mod colors {
    /// Reset all formatting
    pub const RESET: &str = "\x1b[0m";
    /// Bold text
    pub const BOLD: &str = "\x1b[1m";
    /// Dim text
    pub const DIM: &str = "\x1b[2m";

    // Regular colors
    /// Black foreground
    pub const BLACK: &str = "\x1b[30m";
    /// Red foreground
    pub const RED: &str = "\x1b[31m";
    /// Green foreground
    pub const GREEN: &str = "\x1b[32m";
    /// Yellow foreground
    pub const YELLOW: &str = "\x1b[33m";
    /// Blue foreground
    pub const BLUE: &str = "\x1b[34m";
    /// Magenta foreground
    pub const MAGENTA: &str = "\x1b[35m";
    /// Cyan foreground
    pub const CYAN: &str = "\x1b[36m";
    /// White foreground
    pub const WHITE: &str = "\x1b[37m";

    // Bright colors
    /// Bright black foreground
    pub const BRIGHT_BLACK: &str = "\x1b[90m";
    /// Bright red foreground
    pub const BRIGHT_RED: &str = "\x1b[91m";
    /// Bright green foreground
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    /// Bright yellow foreground
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    /// Bright blue foreground
    pub const BRIGHT_BLUE: &str = "\x1b[94m";
    /// Bright magenta foreground
    pub const BRIGHT_MAGENTA: &str = "\x1b[95m";
    /// Bright cyan foreground
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
    /// Bright white foreground
    pub const BRIGHT_WHITE: &str = "\x1b[97m";
}

/// Unicode symbols for visual indicators
pub mod symbols {
    /// Success indicator (check mark)
    pub const CHECK: &str = "✓";
    /// Error indicator (cross mark)
    pub const CROSS: &str = "✗";
    /// Information indicator (info symbol)
    pub const INFO: &str = "ℹ";
    /// Warning indicator (warning triangle)
    pub const WARNING: &str = "⚠";
    /// Right arrow glyph
    pub const ARROW_RIGHT: &str = "→";
    /// Bullet point glyph
    pub const DOT: &str = "•";
    /// Key glyph (used for authentication)
    pub const KEY: &str = "🔑";
    /// Network antenna glyph
    pub const NETWORK: &str = "📡";
    /// Globe glyph (used for public network)
    pub const GLOBE: &str = "🌐";
    /// Rocket glyph (used for startup)
    pub const ROCKET: &str = "🚀";
    /// Hourglass glyph (used for waiting)
    pub const HOURGLASS: &str = "⏳";
    /// Circular arrows glyph (used for retry/progress)
    pub const CIRCULAR_ARROWS: &str = "⟳";
}

/// Box drawing characters for borders
pub mod box_chars {
    /// Top-left box corner
    pub const TOP_LEFT: &str = "╭";
    /// Top-right box corner
    pub const TOP_RIGHT: &str = "╮";
    /// Bottom-left box corner
    pub const BOTTOM_LEFT: &str = "╰";
    /// Bottom-right box corner
    pub const BOTTOM_RIGHT: &str = "╯";
    /// Horizontal line
    pub const HORIZONTAL: &str = "─";
    /// Vertical line
    pub const VERTICAL: &str = "│";
    /// T-junction left
    pub const T_LEFT: &str = "├";
    /// T-junction right
    pub const T_RIGHT: &str = "┤";
}

/// Check if an IPv6 address is link-local (fe80::/10)
fn is_ipv6_link_local(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    (octets[0] == 0xfe) && ((octets[1] & 0xc0) == 0x80)
}

/// Check if an IPv6 address is unique local (fc00::/7)
fn is_ipv6_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    (octets[0] & 0xfe) == 0xfc
}

/// Check if an IPv6 address is multicast (ff00::/8)
fn is_ipv6_multicast(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xff
}

/// Format a peer ID with color (shows first 8 chars)
pub fn format_peer_id(peer_id: &[u8; 32]) -> String {
    let hex = hex::encode(&peer_id[..4]);
    format!("{}{}{}{}", colors::CYAN, hex, "...", colors::RESET)
}

/// Format an address with appropriate coloring
pub fn format_address(addr: &SocketAddr) -> String {
    let color = match addr.ip() {
        IpAddr::V4(ip) => {
            if ip.is_loopback() {
                colors::DIM
            } else if ip.is_private() {
                colors::YELLOW
            } else {
                colors::GREEN
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback() {
                colors::DIM
            } else if ip.is_unspecified() {
                colors::DIM
            } else if is_ipv6_link_local(&ip) {
                colors::YELLOW
            } else if is_ipv6_unique_local(&ip) {
                colors::CYAN
            } else {
                colors::BRIGHT_CYAN
            }
        }
    };

    format!("{}{}{}", color, addr, colors::RESET)
}

/// Format an address as four words with original address in brackets
pub fn format_address_with_words(addr: &SocketAddr) -> String {
    // TODO: Implement four-word encoding or add dependency
    // For now, just return the colored address
    format_address(addr)
}

/// Categorize and describe an IP address
pub fn describe_address(addr: &SocketAddr) -> &'static str {
    match addr.ip() {
        IpAddr::V4(ip) => {
            if ip.is_loopback() {
                "loopback"
            } else if ip.is_private() {
                "private network"
            } else if ip.is_link_local() {
                "link-local"
            } else {
                "public"
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback() {
                "IPv6 loopback"
            } else if ip.is_unspecified() {
                "IPv6 unspecified"
            } else if is_ipv6_link_local(&ip) {
                "IPv6 link-local"
            } else if is_ipv6_unique_local(&ip) {
                "IPv6 unique local"
            } else if is_ipv6_multicast(&ip) {
                "IPv6 multicast"
            } else {
                "IPv6 global"
            }
        }
    }
}

/// Draw a box with title and content
pub fn draw_box(title: &str, width: usize) -> (String, String, String) {
    let padding = width.saturating_sub(title.width() + 4);
    let left_pad = padding / 2;
    let right_pad = padding - left_pad;

    let top = format!(
        "{}{} {} {}{}{}",
        box_chars::TOP_LEFT,
        box_chars::HORIZONTAL.repeat(left_pad),
        title,
        box_chars::HORIZONTAL.repeat(right_pad),
        box_chars::HORIZONTAL,
        box_chars::TOP_RIGHT
    );

    let middle = format!("{} {{}} {}", box_chars::VERTICAL, box_chars::VERTICAL);

    let bottom = format!(
        "{}{}{}",
        box_chars::BOTTOM_LEFT,
        box_chars::HORIZONTAL.repeat(width - 2),
        box_chars::BOTTOM_RIGHT
    );

    (top, middle, bottom)
}

/// Print the startup banner
pub fn print_banner(version: &str) {
    let title = format!("ant-quic v{version}");
    let (top, middle, bottom) = draw_box(&title, 60);

    println!("{top}");
    println!(
        "{}",
        middle.replace(
            "{}",
            "Starting QUIC P2P with NAT Traversal                 "
        )
    );
    println!("{bottom}");
    println!();
}

/// Print a section header
pub fn print_section(icon: &str, title: &str) {
    println!("{} {}{}{}", icon, colors::BOLD, title, colors::RESET);
}

/// Print an item with bullet point
pub fn print_item(text: &str, indent: usize) {
    let indent_str = " ".repeat(indent);
    println!("{}{} {}", indent_str, symbols::DOT, text);
}

/// Print a status line with icon
pub fn print_status(icon: &str, text: &str, color: &str) {
    println!("  {} {}{}{}", icon, color, text, colors::RESET);
}

/// Format bytes into human-readable size
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Format duration into human-readable time
pub fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

/// Format timestamp into HH:MM:SS format
pub fn format_timestamp(_timestamp: std::time::Instant) -> String {
    use std::time::SystemTime;

    // This is a simplified timestamp - in a real app you'd want proper time handling
    let now = SystemTime::now();
    let duration_since_epoch = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO);

    let total_seconds = duration_since_epoch.as_secs();
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

/// Custom log formatter that adds colors and symbols
pub struct ColoredLogFormatter;

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for ColoredLogFormatter
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let metadata = event.metadata();
        let level = metadata.level();

        // Choose color and symbol based on level
        let (color, symbol) = match *level {
            Level::ERROR => (colors::RED, symbols::CROSS),
            Level::WARN => (colors::YELLOW, symbols::WARNING),
            Level::INFO => (colors::GREEN, symbols::CHECK),
            Level::DEBUG => (colors::BLUE, symbols::INFO),
            Level::TRACE => (colors::DIM, symbols::DOT),
        };

        // Write colored output
        write!(&mut writer, "{color}{symbol} ")?;

        // Write the message
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        write!(&mut writer, "{}", colors::RESET)?;

        writeln!(writer)
    }
}

/// Progress indicator for operations
pub struct ProgressIndicator {
    message: String,
    frames: Vec<&'static str>,
    current_frame: usize,
}

impl ProgressIndicator {
    /// Create a new progress indicator with a message
    pub fn new(message: String) -> Self {
        Self {
            message,
            frames: vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            current_frame: 0,
        }
    }

    /// Advance the spinner by one frame and redraw
    pub fn tick(&mut self) {
        print!(
            "\r{} {} {} ",
            self.frames[self.current_frame],
            colors::BLUE,
            self.message
        );
        self.current_frame = (self.current_frame + 1) % self.frames.len();
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
    }

    /// Finish the progress indicator with a success message
    pub fn finish_success(&self, message: &str) {
        println!(
            "\r{} {}{}{} {}",
            symbols::CHECK,
            colors::GREEN,
            self.message,
            colors::RESET,
            message
        );
    }

    /// Finish the progress indicator with an error message
    pub fn finish_error(&self, message: &str) {
        println!(
            "\r{} {}{}{} {}",
            symbols::CROSS,
            colors::RED,
            self.message,
            colors::RESET,
            message
        );
    }
}
