use std::error::Error;
use std::fmt;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct DnsError(String);

impl fmt::Display for DnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for DnsError {}

pub fn dns_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(DnsError(message.into()))
}
