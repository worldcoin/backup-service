use std::sync::Arc;

/// A `tracing` writer that captures emitted log lines into an in-memory buffer
/// so tests can assert on what was logged.
#[derive(Clone, Default)]
pub(crate) struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

impl LogCapture {
    pub(crate) fn dump(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for LogCapture {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}
