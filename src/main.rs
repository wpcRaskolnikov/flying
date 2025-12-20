mod mdns;
mod receive;
mod send;
mod utils;

use std::{env, net::SocketAddr, path::PathBuf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const VERSION: u64 = 2;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    let mode = &args[1];

    match mode.as_str() {
        "send" => {
            if args.len() < 3 {
                println!("Usage: flying send <file>");
                return;
            }
            let file_path = PathBuf::from(&args[2]);

            if !file_path.exists() {
                println!("Error: File does not exist: {:?}", file_path);
                return;
            }

            let password = utils::generate_password();

            println!("===========================================");
            println!("Flying - File Transfer Tool");
            println!("===========================================");
            println!("Mode: SEND");
            println!("Password: {}", password);
            println!("===========================================\n");

            if let Err(e) = run_sender(&file_path, &password).await {
                eprintln!("Error: {}", e);
            }
        }
        "receive" => {
            // Parse options
            let mut i = 2;
            let mut sender_ip: Option<String> = None;
            let mut output_dir = env::current_dir().unwrap();
            let mut password: Option<String> = None;

            while i < args.len() {
                match args[i].as_str() {
                    "-o" => {
                        if i + 1 < args.len() {
                            output_dir = PathBuf::from(&args[i + 1]);
                            i += 2;
                        } else {
                            println!("Error: -o requires an argument");
                            return;
                        }
                    }
                    arg => {
                        if password.is_none() {
                            password = Some(arg.to_string());
                            i += 1;
                        } else if sender_ip.is_none() {
                            sender_ip = Some(arg.to_string());
                            i += 1;
                        } else {
                            i += 1;
                        }
                    }
                }
            }

            let password = match password {
                Some(p) => p,
                None => {
                    println!("Please enter password:");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).unwrap();
                    input.trim().to_string()
                }
            };

            if !output_dir.exists() {
                println!("Error: Output directory does not exist: {:?}", output_dir);
                return;
            }

            println!("===========================================");
            println!("Flying - File Transfer Tool");
            println!("===========================================");
            println!("Mode: RECEIVE");
            println!("Password: {}", password);
            println!("Output directory: {:?}", output_dir);
            println!("===========================================\n");

            if let Err(e) = run_receiver(&output_dir, &password, sender_ip).await {
                eprintln!("Error: {}", e);
            }
        }
        _ => print_usage(),
    }
}

async fn run_sender(file_path: &PathBuf, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = utils::get_key_from_password(password);

    let addr = "0.0.0.0:3290".parse::<SocketAddr>()?;

    // Start mDNS service advertisement
    let _mdns = mdns::advertise_service(3290)?;

    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on {}...", addr);
    println!("Waiting for receiver to connect...\n");

    let (mut stream, socket_addr) = listener.accept().await?;
    println!("Connection accepted from {}\n", socket_addr);

    // Version exchange
    let peer_version = stream.read_u64().await?;
    stream.write_u64(VERSION).await?;

    if peer_version != VERSION {
        println!(
            "Warning: Version mismatch (local: {}, peer: {})",
            VERSION, peer_version
        );
    }

    // Mode confirmation (1 = send, 0 = receive)
    let peer_mode = stream.read_u64().await?;
    if peer_mode == 1 {
        stream.write_u64(0).await?;
        return Err("Both ends selected send mode".into());
    } else {
        stream.write_u64(1).await?;
    }

    // Send number of files (always 1 in this simple version)
    stream.write_u64(1).await?;

    // Send the file
    send::send_file(file_path, &key, &mut stream).await?;

    println!("\n===========================================");
    println!("Transfer complete!");
    println!("===========================================");

    stream.shutdown().await?;
    Ok(())
}

async fn run_receiver(
    output_dir: &PathBuf,
    password: &str,
    sender_ip: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = utils::get_key_from_password(password);

    // Discover sender using mDNS or use provided IP
    let sender_addr = if let Some(ip) = sender_ip {
        format!("{}:3290", ip).parse::<SocketAddr>()?
    } else {
        let services = mdns::discover_services(5)?; // Scan for 5 seconds
        if let Some(selected_service) = mdns::select_service(&services) {
            format!("{}:3290", selected_service.ip).parse::<SocketAddr>()?
        } else {
            return Err("No sender found".into());
        }
    };

    println!("Connecting to sender at {}...", sender_addr);
    let mut stream = TcpStream::connect(sender_addr).await?;
    println!("Connected!\n");

    // Version exchange
    stream.write_u64(VERSION).await?;
    let peer_version = stream.read_u64().await?;

    if peer_version != VERSION {
        println!(
            "Warning: Version mismatch (local: {}, peer: {})",
            VERSION, peer_version
        );
    }

    // Mode confirmation (1 = send, 0 = receive)
    stream.write_u64(0).await?; // We are receiver
    let mode_ok = stream.read_u64().await?;
    if mode_ok != 1 {
        return Err("Both ends selected the same mode".into());
    }

    // Receive number of files
    let num_files = stream.read_u64().await?;
    println!("Receiving {} file(s)...\n", num_files);

    // Receive files
    for i in 0..num_files {
        println!("===========================================");
        println!("File {} of {}", i + 1, num_files);
        println!("===========================================");
        let last_file = i == num_files - 1;
        receive::receive_file(output_dir, &key, &mut stream, last_file).await?;
        println!();
    }

    println!("===========================================");
    println!("Transfer complete!");
    println!("===========================================");

    stream.shutdown().await?;
    Ok(())
}

fn print_usage() {
    println!("Flying - Simple File Transfer Tool\n");
    println!("Usage:");
    println!("  Send a file:");
    println!("    flying send <file>");
    println!("    Example: flying send document.pdf\n");
    println!("  Receive a file:");
    println!("    flying receive [password] [sender_ip] [-o output_directory]");
    println!("    Example: flying receive blue-bird-secret");
    println!("    Example: flying receive blue-bird-secret 192.168.1.100");
    println!("    Example: flying receive blue-bird-secret -o /tmp/downloads");
    println!("    Example: flying receive blue-bird-secret 192.168.1.100 -o /tmp/downloads\n");
    println!("Send Mode Usage:");
    println!("  Starts a TCP server and broadcasts mDNS service:");
    println!("    flying send <file>");
    println!("    - Waits for receiver to connect");
    println!("    - Password is auto-generated using petname\n");
    println!("Receive Mode Usage:");
    println!("  Connects to sender using mDNS discovery or direct IP:");
    println!("    flying receive [password] [sender_ip] [-o output_directory]");
    println!("    - If sender_ip is not provided, mDNS auto-discovery will be used");
    println!("    - If password is not provided, you'll be prompted");
    println!("    - Use -o to specify output directory (default is current directory)\n");
    println!("Note:");
    println!("  - Send mode generates passwords using petname (e.g. blue-bird-secret)");
    println!("  - Receiver connects to sender using mDNS discovery or direct IP");
    println!("  - Default output directory is current directory");
    println!("  - Uses TCP port 3290");
    println!("  - Files are encrypted with AES-256-GCM");
}
