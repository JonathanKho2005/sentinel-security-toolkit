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

def validate_ports(ports, max_ports = 100):
    # Check if ports contains a collection of ports instead of individual characters
    if isinstance(ports, (str,bytes)):
        raise ValueError("Port must be a collection of integers.")

    # Check if max_port is a positive integer, excluding booleans
    if not isinstance(max_ports, int) or isinstance(max_ports, bool) or max_ports < 1:
        raise ValueError("Max ports must be a positive integer.")

    try:
        port_list = list(ports)
    except TypeError as exc:
        raise ValueError("Ports must be iterable of integers.") from exc

    if not port_list:
        raise ValueError("At least one port must be supplied.")

    for port in port_list:
        if (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535):
            raise ValueError(f"Invalid port : {port}. Port must be an integer between 1 and 65535.")

    # Remove duplicates while maintaining the original order.
    port_list = list(dict.fromkeys(port_list))

    if len(port_list) > max_ports:
        raise ValueError(f"Too many ports. The maximum allowed is {max_ports} ports.")

    return port_list