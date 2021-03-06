use netdiag::NetDiag;

fn main() {
    let mut nd = NetDiag::new_tcp();
    println!("{:?}", nd);
    loop {
        match nd.recv() {
            Err(x) => {
				println!("Error {:?}", x)
			}
            Ok(x) => println!("{:?}", x),
        }
    }
}
