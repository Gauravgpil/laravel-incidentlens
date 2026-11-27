pub mod error;
pub mod exit_codes;
pub mod protocol;
pub mod redaction;
pub mod validation;

pub use error::CoreError;
pub use exit_codes::ExitCode;
pub use protocol::{
    is_protocol_compatible, Confidence, Evidence, EvidenceKind, Finding, Incident, ProjectDrivers,
    ProjectMetadata, ProjectReport, ProtocolInfo, RequestEnvelope, RequestOptions,
    ResponseEnvelope, Severity, SummaryCounts, ENGINE_VERSION, PROTOCOL_VERSION,
};
