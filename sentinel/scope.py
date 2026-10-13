import ipaddress

# Only allows scan in localhost by default
default_allowed_targets = [
    "127.0.0.0/8",  # IPv4 loopback
    "::1/128",      # IPv6 loopback
]

def validate_target(host, allowed_targets = None):
    # Check if host IP is in string type, or if it is an empty string
    if not isinstance(host, str) or not host.strip():
        raise ValueError("Target must not be empty.")

    try :
        address = ipaddress.ip_address(host.strip())
    except ValueError as exc:
        raise ValueError("Target must be in the format of an IP address.") from exc

    # Default loopback scope
    allowed_networks = [ipaddress.ip_network(network) for network in default_allowed_targets]

    # Add explicitly authorised targets
    for target in allowed_targets or []:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid target allowed : {target}") from exc

        allowed_networks.append(network)

    # Reject address outside the scope
    permitted = any(address.version == network.version and address in network for network in allowed_networks)

    if not permitted:
        raise PermissionError(f"Target {host} is outside the permission scan scope.")

    return str(address)