use sha2rust::Sha2;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let sha2obj = Sha2::new();

    match args.len() {
	3 => match args[1].as_str() {
	    "-s" => {
		match sha2obj.read_from_string(&args[2]) {
		    Ok(s) => {
			println!("{:?}", s);
		    }
		    Err(_) => {
			eprintln!("Could not read file");
		    }
		}
	    },
	    _ => {
		eprintln!("Pass in string: -s <string>");
	    }
	}
        2 => match sha2obj.read_from_file(&args[1]) {
            Ok(s) => {
                println!("{:?}", s);
            }
            Err(_) => {
                eprintln!("Could not read file");
            }
        },
        _ => {
            println!("<filename> or -s <string> needed");
        }
    };
}
