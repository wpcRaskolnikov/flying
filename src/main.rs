mod receive;
mod send;
mod utils;

use std::{env, net::SocketAddr, path::PathBuf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const VERSION: u64 = 1;

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
            if args.len() < 4 {
                println!("Usage: flying send <file> <receiver_ip>");
                return;
            }
            let file_path = PathBuf::from(&args[2]);
            let receiver_ip = &args[3];

            if !file_path.exists() {
                println!("Error: File does not exist: {:?}", file_path);
                return;
            }

            let password = if args.len() > 4 {
                args[4].clone()
            } else {
                utils::generate_password()
            };

            println!("===========================================");
            println!("Flying - File Transfer Tool");
            println!("===========================================");
            println!("Mode: SEND");
            println!("Password: {}", password);
            println!("===========================================\n");

            if let Err(e) = run_sender(&file_path, receiver_ip, &password).await {
                eprintln!("Error: {}", e);
            }
        }
        "receive" => {
            if args.len() < 2 {
                println!("Usage: flying receive [password] [output_dir]");
                return;
            }

            let password = if args.len() > 2 {
                args[2].clone()
            } else {
                println!("Please enter password:");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                input.trim().to_string()
            };

            let output_dir = if args.len() > 3 {
                PathBuf::from(&args[3])
            } else {
                env::current_dir().unwrap()
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

            if let Err(e) = run_receiver(&output_dir, &password).await {
                eprintln!("Error: {}", e);
            }
        }
        _ => print_usage(),
    }
}

async fn run_sender(
    file_path: &PathBuf,
    receiver_ip: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = utils::get_key_from_password(password);

    let addr = format!("{}:3290", receiver_ip).parse::<SocketAddr>()?;
    println!("Connecting to receiver at {}...", addr);
    let mut stream = TcpStream::connect(addr).await?;
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
    stream.write_u64(1).await?;
    let mode_ok = stream.read_u64().await?;
    if mode_ok != 1 {
        return Err("Both ends selected the same mode".into());
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
) -> Result<(), Box<dyn std::error::Error>> {
    let key = utils::get_key_from_password(password);

    let addr = "0.0.0.0:3290".parse::<SocketAddr>()?;
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on {}...", addr);
    println!("Waiting for connection...\n");

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

    // Mode confirmation
    let peer_mode = stream.read_u64().await?;
    if peer_mode == 0 {
        stream.write_u64(0).await?;
        return Err("Both ends selected receive mode".into());
    } else {
        stream.write_u64(1).await?;
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
    println!("    flying send <file> <receiver_ip> [password]");
    println!("    Example: flying send document.pdf 192.168.1.100 mypass123\n");
    println!("  Receive a file:");
    println!("    flying receive [password] [output_dir]");
    println!("    Example: flying receive mypass123 /tmp/downloads\n");
    println!("Note:");
    println!("  - If password is not provided for send mode, it will be auto-generated");
    println!("  - If password is not provided for receive mode, you'll be prompted");
    println!("  - Default output directory is current directory");
    println!("  - Uses TCP port 3290");
    println!("  - Files are encrypted with AES-256-GCM");
}
