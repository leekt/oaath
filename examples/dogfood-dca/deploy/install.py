"""Run on the owned OCI host as root, with the reviewed release in /tmp/dca-release.
Creates only DCA-owned resources. Secrets are generated here and never printed.
"""
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import subprocess


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def private(path, content):
    pathlib.Path(path).write_text(content)
    os.chmod(path, 0o600)


if os.geteuid() != 0:
    raise SystemExit("root_required")
if subprocess.run(["id", "dca"], capture_output=True).returncode:
    run("useradd", "--system", "--home", "/var/lib/dca", "--shell", "/usr/sbin/nologin", "dca")
for folder in ["/etc/dca", "/var/lib/dca", "/opt/dca"]:
    pathlib.Path(folder).mkdir(exist_ok=True)
    os.chmod(folder, 0o750)
    run("chown", "dca:dca", folder)
envpath = pathlib.Path("/etc/dca/runtime.env")
if not envpath.exists():
    password = secrets.token_hex(32)
    # Values used in SQL consist exclusively of generated hexadecimal strings.
    role = run("sudo", "-u", "postgres", "psql", "-Atqc", "SELECT 1 FROM pg_roles WHERE rolname='dca'")
    if role:
        raise SystemExit("existing_role_requires_retained_configuration")
    run("sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-c", f"CREATE ROLE dca LOGIN PASSWORD '{password}'")
    run("sudo", "-u", "postgres", "createdb", "--owner=dca", "dca")
    token = secrets.token_hex(32)
    values = {
        "AUTOMATION_CONFIG": "/etc/dca/deployment.json",
        "AUTOMATION_DATABASE_URL": f"postgres://dca:{password}@127.0.0.1:5432/dca",
        "AUTOMATION_API_TOKEN": token,
        "AUTOMATION_APPLICATION_HASHES": json.dumps([["dca-example", hashlib.sha256(token.encode()).hexdigest()]], separators=(",", ":")),
        "AUTOMATION_SEAL_KEY": secrets.token_hex(32),
        "AUTOMATION_RUNTIME_TOKEN": secrets.token_hex(32),
        "AUTOMATION_RUNTIME_URL": "http://127.0.0.1:4318",
        "AUTOMATION_ALLOWED_HOSTS": "127.0.0.1:4317",
        "AUTOMATION_BIND": "127.0.0.1:4317",
        "NODE_ENV": "production",
    }
    private(envpath, "\n".join(f"{k}='{v}'" for k, v in values.items()) + "\n")
private("/etc/dca/deployment.json", pathlib.Path("/tmp/dca-release/deployment.json").read_text())
run("chown", "-R", "dca:dca", "/etc/dca")
shutil.copytree("/tmp/dca-release/server", "/opt/dca", dirs_exist_ok=True)
shutil.copy2("/tmp/dca-release/automation-api", "/opt/dca/automation-api.next")
os.chmod("/opt/dca/automation-api.next", 0o755)
os.replace("/opt/dca/automation-api.next", "/opt/dca/automation-api")
run("chown", "-R", "root:dca", "/opt/dca")
for name, command in {
    "api": "/opt/dca/automation-api",
    "runtime": "/opt/node/bin/node --max-old-space-size=128 /opt/dca/runtime/src/main.mjs",
    "gateway": "/opt/node/bin/node --max-old-space-size=96 /opt/dca/gateway.mjs",
}.items():
    after = "network-online.target postgresql.service" + (" dca-api.service" if name != "api" else "")
    pathlib.Path(f"/etc/systemd/system/dca-{name}.service").write_text(f"""[Unit]
Description=DCA {name}
After={after}
StartLimitIntervalSec=300
StartLimitBurst=5
[Service]
Type=simple
User=dca
Group=dca
WorkingDirectory=/opt/dca
EnvironmentFile=/etc/dca/runtime.env
ExecStart={command}
Restart=always
RestartSec=15
TimeoutStopSec=35
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/dca
MemoryMax=180M
[Install]
WantedBy=multi-user.target
""")
run("systemctl", "daemon-reload")
run("systemctl", "enable", "dca-api", "dca-runtime", "dca-gateway")
run("systemctl", "restart", "dca-api")
# Schema creation is completed by the Rust API before other processes start.
import time
import urllib.request
for attempt in range(30):
    try:
        with urllib.request.urlopen("http://127.0.0.1:4317/health", timeout=1) as response:
            if response.status == 200:
                break
    except Exception:
        time.sleep(1)
else:
    raise SystemExit("api_start_failed")
run("systemctl", "restart", "dca-runtime", "dca-gateway")
print("DCA database, private configuration and three boot services installed")
