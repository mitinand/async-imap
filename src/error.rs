//! IMAP error types.

use std::fmt;
use std::io::Error as IoError;
use std::str::Utf8Error;

use base64::DecodeError;
use imap_proto::ResponseCode;

/// A convenience wrapper around `Result` for `imap::Error`.
pub type Result<T> = std::result::Result<T, Error>;

/// A set of errors that can occur in the IMAP client
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// An `io::Error` that occurred while trying to read or write to a network stream.
    #[error("io: {0}")]
    Io(#[from] IoError),
    /// A BAD response from the IMAP server.
    #[error("bad response: {0}")]
    Bad(StatusResponse),
    /// A NO response from the IMAP server.
    #[error("no response: {0}")]
    No(StatusResponse),
    /// A BYE response: the server is closing the connection and says why.
    #[error("bye response: {0}")]
    Bye(StatusResponse),
    /// The connection was terminated unexpectedly.
    #[error("connection lost")]
    ConnectionLost,
    /// Error parsing a server response.
    #[error("parse: {0}")]
    Parse(#[from] ParseError),
    /// Command inputs were not valid [IMAP
    /// strings](https://tools.ietf.org/html/rfc3501#section-4.3).
    #[error("validate: {0}")]
    Validate(#[from] ValidateError),
    /// Error appending an e-mail.
    #[error("could not append mail to mailbox")]
    Append,
}

/// An incoming response is larger than the 512 MiB the client buffers.
///
/// It arrives as the source of an [`Error::Io`] of kind `Other`, so it can be
/// told apart from a response that could not be parsed.
#[derive(thiserror::Error, Debug)]
#[error("incoming data too large")]
pub struct ResponseTooLarge;

/// The response code and text of a NO or BAD response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusResponse {
    /// The response code without its arguments, such as `TRYCREATE`, or a code from
    /// [RFC 5530](https://tools.ietf.org/html/rfc5530) such as `AUTHENTICATIONFAILED`.
    pub code: Option<String>,
    /// The human-readable text after the response code.
    pub text: String,
}

impl StatusResponse {
    pub(crate) fn new(code: Option<&ResponseCode<'_>>, information: Option<&str>) -> Self {
        let information = information.unwrap_or_default();
        if let Some(code) = code {
            return Self {
                code: response_code_name(code).map(str::to_owned),
                text: information.to_owned(),
            };
        }
        // imap-proto does not parse codes it does not know, such as those of
        // RFC 5530; they stay in brackets at the start of the text.
        let unparsed = information
            .strip_prefix('[')
            .and_then(|rest| rest.split_once(']'))
            .and_then(|(code, text)| {
                let name = code.split(' ').next().filter(|name| !name.is_empty())?;
                Some((name, text.strip_prefix(' ').unwrap_or(text)))
            });
        match unparsed {
            Some((name, text)) => Self {
                code: Some(name.to_ascii_uppercase()),
                text: text.to_owned(),
            },
            None => Self {
                code: None,
                text: information.to_owned(),
            },
        }
    }
}

impl fmt::Display for StatusResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.code {
            Some(code) => write!(f, "[{code}] {}", self.text),
            None => f.write_str(&self.text),
        }
    }
}

fn response_code_name(code: &ResponseCode<'_>) -> Option<&'static str> {
    Some(match code {
        ResponseCode::Alert => "ALERT",
        ResponseCode::BadCharset(_) => "BADCHARSET",
        ResponseCode::Capabilities(_) => "CAPABILITY",
        ResponseCode::HighestModSeq(_) => "HIGHESTMODSEQ",
        ResponseCode::Parse => "PARSE",
        ResponseCode::PermanentFlags(_) => "PERMANENTFLAGS",
        ResponseCode::ReadOnly => "READ-ONLY",
        ResponseCode::ReadWrite => "READ-WRITE",
        ResponseCode::TryCreate => "TRYCREATE",
        ResponseCode::UidNext(_) => "UIDNEXT",
        ResponseCode::UidValidity(_) => "UIDVALIDITY",
        ResponseCode::Unseen(_) => "UNSEEN",
        ResponseCode::AppendUid(..) => "APPENDUID",
        ResponseCode::CopyUid(..) => "COPYUID",
        ResponseCode::UidNotSticky => "UIDNOTSTICKY",
        ResponseCode::MetadataLongEntries(_)
        | ResponseCode::MetadataMaxSize(_)
        | ResponseCode::MetadataTooMany
        | ResponseCode::MetadataNoPrivate => "METADATA",
        _ => return None,
    })
}

/// An error occured while trying to parse a server response.
#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    /// Indicates an error parsing the status response. Such as OK, NO, and BAD.
    #[error("unable to parse status response")]
    Invalid(Vec<u8>),
    /// An unexpected response was encountered.
    #[error("encountered unexpected parsed response: {0}")]
    Unexpected(String),
    /// The client could not find or decode the server's authentication challenge.
    #[error("unable to parse authentication response: {0} - {1:?}")]
    Authentication(String, Option<DecodeError>),
    /// The client received data that was not UTF-8 encoded.
    #[error("unable to parse data ({0:?}) as UTF-8 text: {1:?}")]
    DataNotUtf8(Vec<u8>, #[source] Utf8Error),
    /// The expected response for X was not found
    #[error("expected response not found for: {0}")]
    ExpectedResponseNotFound(String),
}

/// An [invalid character](https://tools.ietf.org/html/rfc3501#section-4.3) was found in an input
/// string.
#[derive(thiserror::Error, Debug)]
#[error("invalid character in input: '{0}'")]
pub struct ValidateError(pub char);

#[cfg(test)]
mod tests {
    use super::*;

    fn is_send<T: Send>(_t: T) {}

    #[test]
    fn test_send() {
        is_send::<Result<usize>>(Ok(3));
    }
}
