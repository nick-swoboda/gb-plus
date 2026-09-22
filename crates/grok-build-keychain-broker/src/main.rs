//! Production stable Keychain broker process.

fn main() {
    if let Err(error) = grok_build_keychain_broker::run_production_broker() {
        // Broker errors are deliberately bounded and never contain credential
        // bytes. The app normally receives the framed form over its private
        // Unix socket.
        eprintln!("{error}");
        std::process::exit(2);
    }
}
