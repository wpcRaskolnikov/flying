use std::io::{self, Write};
use tokio::sync::mpsc::Sender;

pub struct Progress {
    total: u64,
    last_percent: u8,
    progress_tx: Option<Sender<u8>>,
}

impl Progress {
    pub fn new(total: u64, progress_tx: Option<Sender<u8>>) -> Self {
        Self {
            total,
            last_percent: 0,
            progress_tx,
        }
    }

    pub fn update(&mut self, bytes_processed: u64) -> io::Result<()> {
        if self.total == 0 {
            return Ok(());
        }
        let percent_done = ((bytes_processed as f64 / self.total as f64) * 100.0) as u8;
        if percent_done > self.last_percent {
            print!("\rProgress: {}%", percent_done);
            io::stdout().flush()?;
            self.last_percent = percent_done;

            if let Some(tx) = &self.progress_tx {
                let _ = tx.try_send(percent_done);
            }
        }
        Ok(())
    }

    pub fn finish(&self) -> io::Result<()> {
        println!("\rProgress: 100%");

        if let Some(tx) = &self.progress_tx {
            let _ = tx.try_send(100);
        }

        Ok(())
    }
}
