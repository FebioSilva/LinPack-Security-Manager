import random
import time
from datetime import datetime, timedelta

# Simulated package list with architectures
packages = [
    ("libc6", "amd64"), ("python3", "amd64"), ("gcc", "amd64"),
    ("libssl1.1", "amd64"), ("curl", "amd64"), ("wget", "amd64"),
    ("nano", "amd64"), ("vim", "amd64"), ("nginx", "amd64"),
    ("postgresql", "amd64"), ("docker-ce", "amd64"),
    ("openssh-server", "amd64"), ("git", "amd64"), ("tmux", "amd64"),
    ("libgl1-mesa-dri", "i386"), ("libnvidia-gl-440", "i386"),
    ("linux-headers-generic", "amd64"), ("nvidia-driver-440", "amd64"),
    ("gnome-software", "amd64"), ("containerd.io", "amd64")
]

# Possible dpkg actions with their sequences
actions = {
    "install": [
        ("status", "half-installed"),
        ("status", "unpacked"),
        ("configure", ""),
        ("status", "half-configured"),
        ("status", "installed")
    ],
    "remove": [
        ("status", "half-configured"),
        ("status", "half-installed"),
        ("status", "config-files"),
        ("status", "not-installed")
    ],
    "upgrade": [
        ("status", "half-configured"),
        ("status", "unpacked"),
        ("status", "half-installed"),
        ("status", "unpacked"),
        ("configure", ""),
        ("status", "half-configured"),
        ("status", "installed")
    ],
    "configure": [
        ("status", "unpacked"),
        ("status", "half-configured"),
        ("status", "installed")
    ],
    "trigproc": [
        ("status", "half-configured"),
        ("status", "installed")
    ]
}

# Generate version numbers
def generate_version():
    major = random.randint(1, 5)
    minor = random.randint(0, 20)
    patch = random.randint(0, 100)
    return f"{major}.{minor}.{patch}"

# Generate random ubuntu version
def generate_ubuntu_version():
    return f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 100)}-0ubuntu{random.randint(1, 5)}~{random.choice(['focal', 'bionic', 'disco'])}"


# Generate a complete dpkg log sequence for an action
def generate_action_sequence(action, package, arch, base_time):
    logs = []
    pkg_name, pkg_arch = package
    version = generate_ubuntu_version() if random.random() > 0.7 else generate_version()

    if action == "upgrade":
        old_version = generate_version()
        logs.append(
            f"{base_time} {action} {pkg_name}:{pkg_arch} {old_version} {version}")
    elif action == "install":
        logs.append(
            f"{base_time} {action} {pkg_name}:{pkg_arch} <none> {version}")
    elif action == "remove":
        logs.append(
            f"{base_time} {action} {pkg_name}:{pkg_arch} {version} <none>")
    else:
        logs.append(
            f"{base_time} {action} {pkg_name}:{pkg_arch} {version} <none>")

    for step in actions[action]:
        if step[0] == "status":
            logs.append(
                f"{base_time} {step[0]} {step[1]} {pkg_name}:{pkg_arch} {version}")
        elif step[0] == "configure":
            logs.append(
                f"{base_time} {step[0]} {pkg_name}:{pkg_arch} {version} <none>")
        elif step[0] == "trigproc":
            logs.append(
                f"{base_time} {step[0]} {pkg_name}:{pkg_arch} {version} <none>")

    return logs

# Generate synthetic logs
def generate_synthetic_logs(count=20):
    logs = []
    base_time = datetime.now()

    for _ in range(count):
        action = random.choice(list(actions.keys()))
        package = random.choice(packages)
        logs.extend(generate_action_sequence(
            action, package, package[1], base_time))

    with open("../../resources/dpkg_synthetic.log", "w") as f:
        f.write("\n".join(logs))
        f.write("\n")
    return


if __name__ == "__main__":
    generate_synthetic_logs(3)
    print("Generated dpkg_synthetic.log with synthetic dpkg log data")
