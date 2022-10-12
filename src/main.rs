use sha2rust::Sha2;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let sha2obj = Sha2::new();

    match args.len() {
        2 => match sha2obj.sum(&args[1]) {
            Ok(s) => {
                println!("{:?}", s);
            }
            Err(_) => {
                eprintln!("Could not read file");
            }
        },
        _ => {
            println!("<filename> needed");
        }
    };
}
