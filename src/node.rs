use std::collections::HashMap;
use uuid::Uuid;
use crate::models::ThreatIndicator;

pub struct Node {
    indicators: HashMap<Uuid, ThreatIndicator>,
    peers: Vec<String>,
}

impl Node {
    pub fn new() -> Self {
        Node {
            indicators: HashMap::new(),
            peers: Vec::new(),
        }
    }

    pub fn bootstrap_peers(&mut self, peers: Vec<String>) {
        for peer in peers {
            self.peers.push(peer);
        }
    }

    pub fn add_indicator(&mut self, indicator: ThreatIndicator) -> Uuid {
        let id = indicator.get_id();
        self.indicators.insert(id, indicator.clone());
        id
    }
    
    pub fn get_indicator(&self, id: &Uuid) -> Option<&ThreatIndicator> {
        self.indicators.get(id)
    }
}