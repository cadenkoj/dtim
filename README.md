# Distributed Threat Intelligence Mesh (DTIM)

**Design Document**

> [!CAUTION]
> This project is a learning endeavor, maintained by a high school student exploring cybersecurity. Please note that the code may not be professionally reviewed or adhere to industry best practices. Use this project for educational purposes, and exercise caution before deploying it in production environments.

---

## 1. Overview

**DTIM** is a decentralized, privacy-preserving platform for organizations to share security threat indicators (IOCs) without revealing sensitive internal details or attribution. Nodes are self-hosted, manually configured, and can communicate privately or via a public, opt-in registry. The system supports custom indicator fields and STIX/TAXII compatibility.

---

## 2. Architecture

### 2.1 System Components

- **Node:**  
  Self-hosted agent that collects, sanitizes, and shares threat indicators detected in the local environment.
- **Registry:**  
  Public, opt-in service for peer discovery and bootstrapping.
- **Gossip Protocol:**  
  Periodic, randomized sharing of indicators between nodes.
- **Privacy Filter:**  
  Ensures no sensitive or identifying information is shared between organizations.
- **STIX Adapter:**  
  Enables compatibility with industry-standard threat intelligence formats.

---

### 2.2 High-Level Flow

1. **Node startup:** Connect to the registry (if used), receives peer list on register and on interval.
2. **Indicator collection:** Node gathers local threat indicators from configured watchers.
3. **Gossip exchange:** On interval, node shares sanitized indicators with random, approved peers.
4. **Peer management:** Nodes update peer lists periodically; all peers are manually approved.
5. **Indicator aging:** Confidence degrades over time; indicators are purged when confidence reaches zero.

---

## 3. Configuration

### 3.1 Example Configuration File (`config/default.toml`)

```toml
[security]
key_rotation_days = 7
tls_cert_path = "certs/server.crt"
tls_key_path = "certs/server.key"

[storage]
encrypted_logs_path = "data/logs"

[network]
gossip_interval_seconds = 60
peers_per_round = 3
default_peers = [
    "https://peer1.example.com:3030",
    "https://peer2.example.com:3030"
]
registry_url = "https://registry.dtim.example.com"

[privacy]
level = "moderate" # Options: "strict", "moderate", "open"
allow_custom_fields = true

[watchers]
ufw_log_path = "/var/log/ufw.log"
fail2ban_log_path = "/var/log/fail2ban.log"
suricata_log_path = "/var/log/suricata/eve.json"
zeek_log_dir = "/opt/zeek/logs/current"
clamav_scan_dir = "/var/tmp/scan"
virustotal_api_key = "YOUR_API_KEY_HERE"
nginx_access_log = "/var/log/nginx/access.log"
nginx_error_log = "/var/log/nginx/error.log"
apache_access_log = "/var/log/apache2/access.log"
apache_error_log = "/var/log/apache2/error.log"
```

**Recommendations:**

- **[security]:**
  - Use strong, unique TLS keys per node.
  - Rotate keys regularly (default: 7 days).
- **[network]:**
  - `gossip_interval_seconds` default: 60 (configurable).
  - `peers_per_round` default: 3 (configurable).
  - All peers must be manually approved.
- **[privacy]:**
  - Default privacy level: "moderate".
  - Allow custom fields for extensibility.
- **[watchers]:**
  - Enable only the log sources relevant to your environment.

---

## 4. Indicator Schema

### 4.1 Internal Schema

```json
{
  "type": "ip",
  "value": "1.2.3.4",
  "confidence": 80,
  "created": "2025-05-17T15:00:00Z",
  "modified": "2025-05-17T16:00:00Z",
  "sightings": 3,
  "tags": ["malware"],
  "tlp": "red",
  "recipients": ["node-2"],
  "custom_fields": {
    "source": "ufw",
    "threat_category": "bruteforce"
  }
}
```

- **STIX/TAXII compatibility** is supported via an adapter (see below).
- **TLP**: "white", "green", "amber", "red"

---

## 5. Privacy & Anonymization

- **No attribution:** Strip org name, org type, and all internal identifiers from shared indicators.
- **No internal context:** Strip out log lines, user IDs, hostnames, or any data that could identify the source.
- **No attack details:** Only share the indicator itself, confidence, and timestamp by default.
- **Configurable privacy level:**
  - **Strict:** Only indicator value and type.
  - **Moderate (default):** Indicator, confidence, timestamp.
  - **Open:** Indicator, confidence, timestamp, tags/context (still no org info).

---

## 6. Gossip Protocol

- **Interval:** Default 60 seconds (configurable).
- **Peers per round:** Default 3 (configurable).
- **Indicator aging:** Confidence degrades over time; purged when confidence reaches zero.
- **Manual peer approval:** All peers must be explicitly approved in config or via GUI.

---

## 7. Authentication & Security

- **Public key authentication:**
  - Each node possesses a unique key pair.
  - Public key is registered with the registry and shared with peers.
  - All communications are signed and/or encrypted using these keys.
- **TLS/mTLS:**
  - Use TLS for all node-to-node and node-to-registry communication.
  - Support mutual TLS for peer authentication.
- **Manual peer approval:**
  - No automatic trust; all peers must be manually approved.

---

## 8. Public Registry & Access Control

- **Registry:** Public, opt-in only.
- **Indicators:** Private by default; access scope can be changed to public or group.
- **Fields:**
  - `tlp`: "white", "green", "amber", "red"
  - `created`, `modified`: Timestamps for audit and access control.

---

## 9. STIX Adapter

### 9.1 Mapping Example

| Internal Field | STIX/TAXII Field                                |
| -------------- | ----------------------------------------------- |
| type           | type (e.g., "indicator")                        |
| value          | pattern (e.g., `[ipv4-addr:value = '1.2.3.4']`) |
| confidence     | confidence                                      |
| created        | created                                         |
| modified       | modified                                        |
| tags           | labels                                          |
| tlp            | granular_markings (custom)                      |
| recipients     | recipients                                      |
| custom_fields  | extensions                                      |

### 9.2 Example Conversion (Python-like pseudocode)

```python
def to_stix(self):
	# Not implemented: omit keys based on node-defined privacy level
    stix_obj = {
        "type": "indicator",
        "id": f"indicator--{self.id}",  # UUIDv7 primary key
        "created": self.created,
        "modified": self.modified,
        "labels": self.tags,
        "confidence": self.confidence,
        "pattern": self.build_pattern(),
        "extensions": self.custom_fields,
        "granular_markings": [
            {"marking_ref": self.tlp}   # instantiate tlp marking
        ]
    }
    return stix_obj
```

---

## 10. API Contract

### 10.1 Node-to-Registry API

#### **Register Node**

- **POST** `/api/v1/nodes/register`
- **Request:**
  ```json
  {
    "public_key": "base64-encoded-key",
    "endpoint": "https://node.example.com:3030"
  }
  ```
- **Response:**
  ```json
  {
    "status": "ok",
    "peers": [
      { "endpoint": "https://peer1.example.com:3030", "public_key": "..." },
      { "endpoint": "https://peer2.example.com:3030", "public_key": "..." }
    ]
  }
  ```

#### **Get Peer List**

- **GET** `/api/v1/peers`
- **Response:**
  ```json
  [
    { "endpoint": "https://peer1.example.com:3030", "public_key": "..." },
    { "endpoint": "https://peer2.example.com:3030", "public_key": "..." }
  ]
  ```

---

### 10.2 Node-to-Node API

#### **Gossip Indicators**

- **POST** `/api/v1/indicators/gossip`
- **Request:**
  ```json
  {
    "indicators": [ ... ],  // List of sanitized indicators
    "signature": "base64-encoded-signature"
  }
  ```
- **Response:**
  ```json
  {
    "status": "ok",
    "received": 12
  }
  ```

#### **Fetch Public Indicators**

- **GET** `/api/v1/indicators/public`
- **Response:**
  ```json
  [
    { ... }, // List of public indicators
  ]
  ```

#### **Peer Approval (Manual/Out-of-Band)**

- Peers are added to the config file or via configuration GUI.
- No automatic peer approval.

---

## 11. Extensibility & Future Work

- SaaS main registrar
- **Support for new indicator types and custom fields**
- **Integration with SIEM/SOAR tools**
- \*\*Web dashboard for visualization & analytics
- **Federated registries**
- **Advanced privacy (differential privacy, zero-knowledge proofs)**
- **Reputation system for peer reliability**

---

## 12. References

- [STIX/TAXII Documentation](https://oasis-open.github.io/cti-documentation/)
- [Kademlia DHT](https://en.wikipedia.org/wiki/Kademlia)
- [Gossip Protocols](https://en.wikipedia.org/wiki/Gossip_protocol)
- [TOML Configuration](https://toml.io/en/)

---

## 13. Open Questions / To Be Determined

- Peer management UI/UX
- Indicator confidence degradation algorithm
- Registry scaling and centralization

---

## 14. Security

If you believe you have found a security vulnerability in DTIM, we encourage you to **_responsibly disclose this and NOT open a public issue_**. We will investigate all legitimate reports.

Our preference is that you make use of GitHub's private vulnerability reporting feature to disclose potential security vulnerabilities in our Open Source Software. To do this, please visit [https://github.com/cadenkoj/dtim/security](https://github.com/cadenkoj/dtim/security) and click the "Report a vulnerability" button.
