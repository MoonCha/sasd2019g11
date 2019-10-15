use std::fs;
use std::env;


fn print_flag() {
  let contents = fs::read_to_string("flag.txt");
  println!("{:?}", contents);
}

fn add_two_numbers(number1: i32,number2: i32) -> i32 {
    return number1 + number2;
}

fn main() {
  let args: Vec<String> = env::args().collect();
  match args.len() {
    // no arguments passed
    1 => {
        println!("Welcome to our super unhackable RUST example which sums up to a constant offset (1337)");
        println!("Usage:");
        println!("{} <number>", args[0]);
    },
    2 => {
        let n1 = &args[1];
        let offset : i32 = 1337;
        // parse the number
        let number: i32 = match n1.parse() {
            Ok(n) => {
                n
            },
            Err(_) => {
                eprintln!("error: second argument not an integer");
                return;
            },
        };

        // we only allow positive numbers
        if number < 0 {
            println!("Nope");
            return;
        }

        let sum = add_two_numbers(number, offset);

        // Sanity check, should never happen - RUST checks for OOB
        if sum < number {
            println!("What just happened?");
            print_flag();
        } else {
            println!("{:?}",sum);
        }
    },
        // all the other cases
        _ => {
            // show a help message
            println!("Invalid arguments!");
        }
    }
}
