import subprocess
import xml.etree.ElementTree as ET
import docker


NETWORK_NAME = "cyber-lab"
SCAN_RANGE = "172.19.0.0/24"

client = docker.from_env()


def discover_hosts():
    """
    Discover live hosts inside the controlled Docker lab network.
    """

    command = [
        "nmap",
        "-sn",
        "-oX",
        "-",
        SCAN_RANGE
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    root = ET.fromstring(result.stdout)

    hosts = []

    for host in root.findall("host"):
        status = host.find("status")

        if status is None or status.get("state") != "up":
            continue

        address = host.find("address")

        if address is None:
            continue
        ip = address.get("addr")


        hosts.append({
            "ip": ip,
            "status": "up"
        })

    # Add Docker container names where available
    try:
        network = client.networks.get(NETWORK_NAME)
        network_info = network.attrs.get("Containers", {})

        for container_id, data in network_info.items():
            container_ip = data.get("IPv4Address", "").split("/")[0]

            for host in hosts:
                if host["ip"] == container_ip:
                    host["hostname"] = data.get(
                        "Name",
                        container_id[:12]
                    ).lstrip("/")
    except Exception:
        pass


    return hosts
def scan_host(ip):
    """
    Perform service and version discovery against one
    selected host inside the controlled lab network.
    """

    command = [
        "nmap",
        "-sV",
        "--open",
        "-oX",
        "-",
        ip
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    root = ET.fromstring(result.stdout)

    ports = []

    for port in root.findall(".//port"):
        state = port.find("state")
        service = port.find("service")

        if state is None or state.get("state") != "open":
            continue

        service_data = {
            "port": int(port.get("portid")),
            "protocol": port.get("protocol"),
            "state": "open",
            "service": None,
            "product": None,
            "version": None
        }

        if service is not None:
            service_data["service"] = service.get("name")
            service_data["product"] = service.get("product")
            service_data["version"] = service.get("version")

        ports.append(service_data)

    return {
        "ip": ip,
        "ports": ports,
        "count": len(ports)
    }
import socket
import ssl
import ipaddress


def assess_service(ip, port, service=None):
    """
    Perform a controlled, non-destructive initial assessment
    of a selected service inside the isolated lab network.
    """

    target_ip = ipaddress.ip_address(ip)

    if target_ip not in ipaddress.ip_network("172.19.0.0/24"):
        raise ValueError("Target IP is outside the controlled lab network.")

    port = int(port)

    if port < 1 or port > 65535:
        raise ValueError("Invalid port number.")

    result = {
        "ip": ip,
        "port": port,
        "service": service,
        "reachable": False,
        "protocol": "TCP",
        "details": []
    }

    # Basic TCP reachability test
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)

    try:
        sock.connect((ip, port))

        result["reachable"] = True

        result["details"].append(
            "TCP connection established successfully."
        )

    except Exception as e:

        result["details"].append(
            f"TCP connection failed: {str(e)}"
        )

        return result

    finally:
        sock.close()

    # HTTP assessment
    if service and service.lower() in ("http", "http-proxy"):

        http_sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        http_sock.settimeout(3)

        try:

            http_sock.connect((ip, port))

            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"Connection: close\r\n\r\n"
            )

            http_sock.sendall(request.encode())

            response = http_sock.recv(4096).decode(
                "utf-8",
                errors="replace"
            )

            first_line = (
                response.splitlines()[0]
                if response
                else ""
            )

            result["details"].append(
                f"HTTP response: {first_line or 'No response'}"
            )

        except Exception as e:

            result["details"].append(
                f"HTTP assessment failed: {str(e)}"
            )

        finally:
            http_sock.close()

    # HTTPS / TLS assessment
    elif service and service.lower() in ("https", "ssl/http"):

        raw_sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        raw_sock.settimeout(3)

        try:

            context = ssl.create_default_context()

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with context.wrap_socket(
                raw_sock,
                server_hostname=ip
            ) as tls_sock:

                result["details"].append(
                    f"TLS version: {tls_sock.version()}"
                )

                cipher = tls_sock.cipher()

                if cipher:
                    result["details"].append(
                        f"Cipher: {cipher[0]}"
                    )

        except Exception as e:

            result["details"].append(
                f"TLS assessment failed: {str(e)}"
            )

    # Generic TCP service
    else:

        result["details"].append(
            "Service is TCP reachable."
        )

        result["details"].append(
            "No protocol-specific probe was performed."
        )

    return result
