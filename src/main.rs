use std::env;

pub mod sha2;

fn main() {
    let args: Vec<String> = env::args().collect();

    let sha2obj = sha2::Sha2::new();

    match args.len() {
	2 => {
	    sha2obj.algo(&args[1]);
	}
	_ => {
	    println!("<filename> needed");
	}
    };
}
