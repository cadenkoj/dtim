mod models;
mod node;

fn main() {
    let indicator = models::ThreatIndicator::new(
        models::IndicatorType::Ipv4Address,
        "192.168.1.1".to_string(),
        100,
        1,
        vec!["test".to_string()]
    );

    let mut node = node::Node::new();
    node.bootstrap_peers(vec!["https://peer1.example.com:3030".to_string(), "https://peer2.example.com:3030".to_string()]);
    node.add_indicator(indicator.clone());
    println!("{:?}", node.get_indicator(&indicator.get_id()).unwrap());
}
