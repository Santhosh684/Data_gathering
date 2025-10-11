import json

def extract_recon_info_from_file(filename):
    # Load JSON data from file
    with open(filename, 'r') as f:
        data = json.load(f)

    recon = data.get("recon_data", {})

    # Basic system info
    os_name = recon.get("os_name", "")
    os_version = recon.get("os_version", "")
    os_release = recon.get("os_release", "")
    arch = recon.get("architecture", "")
    hostname = recon.get("hostname", "")
    user = recon.get("current_user", "").lower()
    is_privileged = recon.get("is_admin", False)

    # Open ports
    open_ports = recon.get("open_ports", [])
    risky_ports = {22: "SSH", 3389: "RDP", 445: "SMB", 139: "NetBIOS", 5985: "WinRM"}
    detected_services = []
    for port in open_ports:
        service = risky_ports.get(port)
        if service:
            detected_services.append(f"{service} (port {port})")

    # Environment variables (basic inspection)
    env_vars = recon.get("env_vars", {})
    interesting_env = {}
    for k, v in env_vars.items():
        if any(keyword in k.lower() for keyword in ["path", "python", "cuda", "git", "java"]):
            interesting_env[k] = v

    # Build report
    report = {
        "privileged_user": is_privileged,
        "username": user,
        "hostname": hostname,
        "os": f"{os_name} {os_release} ({os_version})",
        "architecture": arch,
        "detected_risky_services": detected_services,
        "interesting_env_vars": interesting_env,
        "recommendations": []
    }

    # Recommendations
    if is_privileged:
        report["recommendations"].append("Active privileged account detected.")
    if detected_services:
        report["recommendations"].append(
            f"Check {', '.join(detected_services)} for weak credentials or misconfigurations."
        )
    if interesting_env:
        report["recommendations"].append("Review PATH, Python, CUDA, and Java-related environment variables.")

    return json.dumps(report, indent=4)


# Example Usage:
if __name__ == "__main__":
    filename = "data.json"  # file containing your JSON
    print(extract_recon_info_from_file(filename))
