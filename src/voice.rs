use rodio::source::SineWave;
use rodio::{Decoder, OutputStream, Sink, Source};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::thread;
use std::time::Duration;

pub fn play_alert_sound<P: AsRef<Path>>(sound_path: P) {
    let path = sound_path.as_ref().to_path_buf();

    thread::spawn(move || {
        if let Ok((_stream, stream_handle)) = OutputStream::try_default() {
            if let Ok(sink) = Sink::try_new(&stream_handle) {
                if path.exists() {
                    if let Ok(file) = File::open(&path) {
                        if let Ok(source) = Decoder::new(BufReader::new(file)) {
                            sink.append(source);
                            sink.sleep_until_end();
                            return;
                        }
                    }
                }

                // Fallback: Synthetic notification tone (sine wave chime)
                let source1 = SineWave::new(523.25)
                    .take_duration(Duration::from_millis(120))
                    .amplify(0.2);
                let source2 = SineWave::new(659.25)
                    .take_duration(Duration::from_millis(150))
                    .amplify(0.25);

                sink.append(source1);
                sink.append(source2);
                sink.sleep_until_end();
            }
        }
    });
}
