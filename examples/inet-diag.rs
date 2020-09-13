use netdiag::NetDiag;

fn main() {
    let mut nd = NetDiag::new_tcp();
    println!("{:?}", nd);
    loop {
        match nd.recv() {
            None => {}
            Some(x) => println!("{:?}", x),
        }
    }
}
