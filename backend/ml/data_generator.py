import random

FEATURES = [
    "packetSize",
    "bytesIn",
    "bytesOut",
    "duration",
    "packetsIn",
    "packetsOut",
    "flagCount",
    "ttl"
]

def generate_packet(force_anomaly=None):
    """
    Create one fake network packet.
    force_anomaly = True  → always attack
    force_anomaly = False → always normal
    force_anomaly = None  → 8% chance of attack
    """

    # Decide if this packet is an attack or not
    if force_anomaly is None:
        is_anomaly = random.random() < 0.08   
    else:
        is_anomaly = force_anomaly

    if not is_anomaly:
        4
        return {
            "packetSize"  : round(random.uniform(200, 1000), 1),
            "bytesIn"     : round(random.uniform(500, 4500), 1),
            "bytesOut"    : round(random.uniform(200, 2000), 1),
            "duration"    : round(random.uniform(0.01, 2.0),  4),
            "packetsIn"   : random.randint(1, 20),
            "packetsOut"  : random.randint(1, 15),
            "flagCount"   : random.randint(0, 2),
            "ttl"         : random.randint(60, 128),
            "protocol"    : random.choice(["TCP", "UDP", "ICMP"]),
            "port"        : random.choice([80, 443, 53, 22, 25]),
            "isAnomaly"   : False,
            "label"       : "Normal"
        }

    # Attack traffic — pick one of 4 attack types
    attack_type = random.randint(0, 3)

    if attack_type == 0:
        # DDoS Flood — huge traffic volume
        return {
            "packetSize"  : round(random.uniform(8000, 10000), 1),
            "bytesIn"     : round(random.uniform(50000, 100000), 1),
            "bytesOut"    : round(random.uniform(50, 150), 1),
            "duration"    : round(random.uniform(0.001, 0.005), 5),
            "packetsIn"   : random.randint(500, 1000),
            "packetsOut"  : random.randint(1, 3),
            "flagCount"   : 0,
            "ttl"         : 255,
            "protocol"    : "UDP",
            "port"        : random.randint(1, 65535),
            "isAnomaly"   : True,
            "label"       : "DDoS Flood"
        }

    elif attack_type == 1:
        # Port Scan — tiny packets, thousands of ports
        return {
            "packetSize"  : round(random.uniform(40, 80), 1),
            "bytesIn"     : round(random.uniform(40, 80), 1),
            "bytesOut"    : round(random.uniform(40, 80), 1),
            "duration"    : round(random.uniform(0.0001, 0.001), 6),
            "packetsIn"   : 1,
            "packetsOut"  : random.randint(500, 1500),
            "flagCount"   : random.randint(6, 10),
            "ttl"         : 128,
            "protocol"    : "TCP",
            "port"        : random.randint(1, 65535),
            "isAnomaly"   : True,
            "label"       : "Port Scan"
        }

    elif attack_type == 2:
        # Data Exfiltration — huge outbound data
        return {
            "packetSize"  : round(random.uniform(1200, 1600), 1),
            "bytesIn"     : round(random.uniform(200, 600), 1),
            "bytesOut"    : round(random.uniform(50000, 100000), 1),
            "duration"    : round(random.uniform(30, 300), 2),
            "packetsIn"   : random.randint(3, 8),
            "packetsOut"  : random.randint(100, 300),
            "flagCount"   : 1,
            "ttl"         : 64,
            "protocol"    : "HTTP",
            "port"        : 21,
            "isAnomaly"   : True,
            "label"       : "Data Exfil"
        }

    else:
        # Suspicious — weird ports, low TTL
        return {
            "packetSize"  : round(random.uniform(400, 700), 1),
            "bytesIn"     : round(random.uniform(1500, 4000), 1),
            "bytesOut"    : round(random.uniform(800, 2500), 1),
            "duration"    : round(random.uniform(0.5, 3.0), 3),
            "packetsIn"   : random.randint(8, 25),
            "packetsOut"  : random.randint(5, 15),
            "flagCount"   : random.randint(4, 8),
            "ttl"         : random.randint(20, 40),
            "protocol"    : random.choice(["TCP", "UDP"]),
            "port"        : random.choice([23, 4444, 1337]),
            "isAnomaly"   : True,
            "label"       : "Suspicious"
        }


def generate_dataset(n=300):
    """Generate n packets with realistic mix of normal and attack."""
    return [generate_packet() for _ in range(n)]


def packets_to_matrix(packets):
    """
    Convert list of packet dicts into a 2D list of numbers.
    ML model only works with numbers — not text.
    Each row = one packet, each column = one feature.
    """
    return [[p[f] for f in FEATURES] for p in packets]
