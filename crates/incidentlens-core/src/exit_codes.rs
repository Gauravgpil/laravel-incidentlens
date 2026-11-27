/// Standard CLI exit codes for Laravel IncidentLens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Successful execution with no threshold-breaking findings.
    Success = 0,
    /// Diagnostic findings exceeded configured CI thresholds.
    ThresholdExceeded = 1,
    /// Invalid CLI arguments, malformed protocol input, or invalid configuration.
    InvalidInput = 2,
    /// Internal engine error.
    InternalError = 3,
    /// Unsupported or incompatible project or protocol version.
    UnsupportedProject = 4,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }
}
