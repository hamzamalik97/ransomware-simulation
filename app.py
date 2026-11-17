from flask import Flask, render_template, jsonify, request
from recon_engine import (
    discover_hosts,
    scan_host,
    assess_service
)
import docker
import ipaddress
import paramiko
from lab_controller import (
    discover_files,
    read_file,
    write_file,
    delete_file
)

from ransomware_engine import (
    generate_key,
    save_key,
    load_key,
    encrypt_data,
    decrypt_data
)


app = Flask(__name__)

client = docker.from_env()

VICTIM = "locker-victim"


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/status")
def status():

    try:

        container = client.containers.get(VICTIM)

        return jsonify({
            "success": True,
            "container": container.name,
            "status": container.status,
            "id": container.short_id
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        })

@app.route("/api/recon/hosts")
def recon_hosts():
    try:
        hosts = discover_hosts()

        return jsonify({
            "success": True,
            "network": "cyber-lab",
            "scan_range": "172.19.0.0/24",
            "hosts": hosts,
            "count": len(hosts)
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })
@app.route("/api/recon/scan", methods=["GET"])
def recon_scan():
    try:
        ip = request.args.get("ip")

        if not ip:
            return jsonify({
                "success": False,
                "error": "No host IP provided."
            }), 400

        result = scan_host(ip)

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
@app.route("/api/recon")
def recon():

    try:

        container = client.containers.get(VICTIM)

        container.reload()

        networks = container.attrs["NetworkSettings"]["Networks"]

        network_info = []

        for network_name, data in networks.items():

            network_info.append({
                "network": network_name,
                "ip": data.get("IPAddress"),
                "gateway": data.get("Gateway")
            })

        return jsonify({
            "success": True,
            "victim": container.name,
            "status": container.status,
            "networks": network_info
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        })


@app.route("/api/discover")
def discover():

    try:

        files = discover_files()

        return jsonify({
            "success": True,
            "files": files,
            "count": len(files)
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        })


@app.route("/api/encrypt")
def encrypt():

    try:

        files = discover_files()

        if not files:

            return jsonify({
                "success": False,
                "error": "No files available for encryption."
            })

        key = generate_key()

        save_key(key)

        encrypted_files = []

        for filepath in files:

            original_data = read_file(filepath)

            encrypted_data = encrypt_data(
                original_data,
                key
            )

            locked_path = filepath + ".locked"

            write_file(
                locked_path,
                encrypted_data
            )

            delete_file(filepath)

            encrypted_files.append(locked_path)

        return jsonify({
            "success": True,
            "count": len(encrypted_files),
            "files": encrypted_files
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        })


@app.route("/api/lock")
def lock_victim():

    try:

        container = client.containers.get(VICTIM)

        container.exec_run(
            [
                "sh",
                "-c",
                "echo 'SYSTEM LOCKED - CONTROLLED LAB SIMULATION' > /locker_data/LOCK_SCREEN.txt"
            ]
        )

        return jsonify({
            "success": True,
            "message": "Victim lock activated."
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        })


@app.route("/api/recover")
def recover():

    try:

        key = load_key()

        container = client.containers.get(VICTIM)

        result = container.exec_run(
            [
                "sh",
                "-c",
                "find /locker_data -type f -name '*.locked' -print"
            ]
        )

        output = result.output.decode().strip()

        if not output:

            return jsonify({
                "success": False,
                "error": "No encrypted files found."
            })

        locked_files = output.splitlines()

        recovered_files = []

        for locked_path in locked_files:

            encrypted_data = read_file(locked_path)

            original_data = decrypt_data(
                encrypted_data,
                key
            )

            original_path = locked_path[:-7]

            write_file(
                original_path,
                original_data
            )

            delete_file(locked_path)

            recovered_files.append(original_path)

        container.exec_run(
            [
                "sh",
                "-c",
                "rm -f /locker_data/LOCK_SCREEN.txt"
            ]
        )

        return jsonify({
            "success": True,
            "count": len(recovered_files),
            "files": recovered_files,
            "lock_removed": True
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        })
@app.route("/api/reset")
def reset_lab():

    try:

        container = client.containers.get(VICTIM)

        # Remove encrypted files
        container.exec_run(
            [
                "sh",
                "-c",
                "find /locker_data -type f -name '*.locked' -delete"
            ]
        )

        # Remove lock screen
        container.exec_run(
            [
                "sh",
                "-c",
                "rm -f /locker_data/LOCK_SCREEN.txt"
            ]
        )

        # Recreate clean demonstration files
        container.exec_run(
            [
                "sh",
                "-c",
                "printf '%s\\n' 'User documents' > /locker_data/document.txt"
            ]
        )

        container.exec_run(
            [
                "sh",
                "-c",
                "printf '%s\\n' 'Confidential training document' > /locker_data/report.txt"
            ]
        )

        container.exec_run(
            [
                "sh",
                "-c",
                "printf '%s\\n' 'Cyber Security Lab Data' > /locker_data/notes.txt"
            ]
        )

        return jsonify({
            "success": True,
            "message": "Lab reset successfully.",
            "files": [
                "/locker_data/document.txt",
                "/locker_data/report.txt",
                "/locker_data/notes.txt"
            ]
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/api/recon/assess", methods=["GET"])
def recon_assess():
    try:

        data = request.get_json(silent=True) or {}
        ip = data.get("ip") or request.args.get("ip")
        port = data.get("port") or request.args.get("port")
        service = data.get("service") or request.args.get("service")
        password = data.get("password")

        if not ip:
            return jsonify({
                "success": False,
                "error": "No host IP provided."
            }), 400

        if not port:
            return jsonify({
                "success": False,
                "error": "No port provided."
            }), 400

        result = assess_service(
            ip,
            port,
            service
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

def controlled_initial_access(ip, port, service):

    allowed_network = "172.19.0.0/24"

    target = ipaddress.ip_address(ip)

    if target not in ipaddress.ip_network(allowed_network):
        raise ValueError(
            "Target is outside the controlled lab network."
        )

    port = int(port)

    if port < 1 or port > 65535:
        raise ValueError("Invalid port.")

    return {
        "ip": ip,
        "port": port,
        "service": service,
        "status": "selected",
        "message": (
            f"Selected {service} service on "
            f"{ip}:{port} for controlled initial access."
        )
    }

def controlled_ssh_access(ip, port, password):
    """
    Controlled SSH access demonstration for the isolated cyber lab.
    """

    allowed_network = ipaddress.ip_network("172.19.0.0/24")
    target_ip = ipaddress.ip_address(ip)

    if target_ip not in allowed_network:
        raise ValueError(
            "Target is outside the controlled lab network."
        )

    port = int(port)

    if port < 1 or port > 65535:
        raise ValueError("Invalid port.")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    try:

        ssh.connect(
            hostname=ip,
            port=port,
            username="labuser",
            password=password,
            timeout=5,
            allow_agent=False,
            look_for_keys=False
        )

        stdin, stdout, stderr = ssh.exec_command(
            "echo CYBER_LAB_SSH_ACCESS_CONFIRMED"
        )

        output = stdout.read().decode().strip()

        return {
            "status": "access_confirmed",
            "ip": ip,
            "port": port,
            "service": "ssh",
            "verification": output
        }

    finally:

        ssh.close()

def controlled_http_access(ip, port):
    """
    Controlled HTTP access demonstration for the isolated cyber lab.
    """

    allowed_network = ipaddress.ip_network("172.19.0.0/24")
    target_ip = ipaddress.ip_address(ip)

    if target_ip not in allowed_network:
        raise ValueError(
            "Target is outside the controlled lab network."
        )

    port = int(port)

    if port < 1 or port > 65535:
        raise ValueError("Invalid port.")

    import urllib.request

    url = f"http://{ip}:{port}/"

    request = urllib.request.Request(
        url,
        method="GET"
    )

    with urllib.request.urlopen(
        request,
        timeout=5
    ) as response:

        body = response.read(200).decode(
            "utf-8",
            errors="replace"
        )

        return {
            "status": "access_confirmed",
            "ip": ip,
            "port": port,
            "service": "http",
            "http_status": response.status,
            "server": response.headers.get(
                "Server",
                "Unknown"
            ),
            "response_preview": body
        }
@app.route("/api/ssh-auth-test", methods=["POST"])
def ssh_auth_test():
    try:
        data = request.get_json(silent=True) or {}
        ip = data.get("ip")
        port = data.get("port")
        username = data.get("username", "labuser")
        password = data.get("password")

        if not ip or not port or not password:
            return jsonify({
                "success": False,
                "error": "Target IP, port, and lab password are required."
            }), 400

        if username != "labuser":
            return jsonify({
                "success": False,
                "error": "Only the dedicated labuser account is allowed."
            }), 400

        result = controlled_ssh_access(ip, port, password)
        return jsonify({
            "success": True,
            "message": "SSH authentication confirmed.",
            "result": result
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 401




@app.route("/api/dictionary-demo", methods=["POST"])
def dictionary_attack_demo():
    import random

    try:
        uploaded = request.files.get("dictionary")
        if uploaded is None or not uploaded.filename.lower().endswith(".txt"):
            return jsonify({
                "success": False,
                "error": "Choose a TXT dictionary file."
            }), 400

        raw = uploaded.stream.read(65537)
        if len(raw) > 65536:
            return jsonify({
                "success": False,
                "error": "Demo files must be no larger than 64 KB."
            }), 400

        entries = [
            line.strip()
            for line in raw.decode("utf-8-sig", errors="replace").splitlines()
            if line.strip()
        ]

        if not entries:
            return jsonify({
                "success": False,
                "error": "The TXT file contains no entries."
            }), 400

        if len(entries) > 500:
            return jsonify({
                "success": False,
                "error": "Use no more than 500 non-empty entries."
            }), 400

        # Shuffle demonstration labels only. No SSH authentication occurs.
        random.shuffle(entries)
        match_at = random.randint(13, 15)
        attempts_to_show = min(match_at, len(entries))

        attempts = [
            {
                "attempt": i,
                "candidate": f"Candidate {i:03d}",
                "status": (
                    "SIMULATED MATCH"
                    if i == match_at
                    else "SIMULATED FAILURE"
                )
            }
            for i in range(1, attempts_to_show + 1)
        ]

        matched = attempts_to_show == match_at

        return jsonify({
            "success": True,
            "simulated": True,
            "entries_loaded": len(entries),
            "attempts_shown": attempts_to_show,
            "matched": matched,
            "attempts": attempts,
            "message": (
                f"SIMULATION ONLY: demonstration match at attempt {match_at}. "
                "No password was tested against SSH; no login occurred."
                if matched else
                "SIMULATION ONLY: fewer than 13 entries were available, "
                "so no match was shown. No SSH login occurred."
            )
        })
    except Exception:
        return jsonify({
            "success": False,
            "error": "Could not process the TXT file."
        }), 400


@app.route("/api/attack", methods=["GET", "POST"])
def initial_access():

    try:

        ip = request.args.get("ip")
        port = request.args.get("port")
        service = request.args.get("service")

        if not ip or not port or not service:
            return jsonify({
                "success": False,
                "error": "IP, port, and service are required."
            }), 400
        if service.lower() == "ssh":

            if not password:
                return jsonify({
                    "success": False,
                    "error": "Run the SSH authentication test first."
                }), 400

            result = controlled_ssh_access(
                ip,
                port,
                password
            )

        elif service.lower() in ["http", "http-proxy"]:

            result = controlled_http_access(
                ip,
                port
            )

        else:

            return jsonify({
                "success": False,
                "error": (
                    f"No controlled initial-access handler "
                    f"has been implemented for {service} yet."
                )
            }), 400


        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
