
import json
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8765

BASE = Path(__file__).resolve().parent
HTML_FILE = BASE / "index.html"

scan_running = False
scan_error = None
lock = threading.Lock()


def powershell(command, timeout=30):
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive",
         "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Error de PowerShell"
        )

    return result.stdout.strip()


def start_scan():
    global scan_running, scan_error

    try:
        powershell("Start-MpScan -ScanType QuickScan", 7200)
        with lock:
            scan_error = None
    except Exception as exc:
        with lock:
            scan_error = str(exc)
    finally:
        with lock:
            scan_running = False


def get_status():
    output = powershell(
        "Get-MpComputerStatus | "
        "Select-Object AntivirusEnabled,"
        "RealTimeProtectionEnabled,"
        "AntivirusSignatureLastUpdated | "
        "ConvertTo-Json",
        30
    )
    return json.loads(output)


def get_threats():
    output = powershell(
        "@(Get-MpThreatDetection | "
        "Select-Object ThreatID,InitialDetectionTime,"
        "ActionSuccess,Resources) | "
        "ConvertTo-Json -Depth 4",
        30
    )

    if not output:
        return []

    data = json.loads(output)
    return data if isinstance(data, list) else [data]


class CleanerHandler(BaseHTTPRequestHandler):

    def send_json(self, data, status=200):
        body = json.dumps(
            data, ensure_ascii=False
        ).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type", "application/json; charset=utf-8"
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            if self.path == "/api/status":
                self.send_json({
                    "ok": True,
                    "defender": get_status()
                })

            elif self.path == "/api/threats":
                self.send_json({
                    "ok": True,
                    "threats": get_threats()
                })

            elif self.path == "/api/scan":
                with lock:
                    running = scan_running
                    error = scan_error

                self.send_json({
                    "ok": True,
                    "running": running,
                    "error": error
                })

            elif self.path in ("/", "/index.html"):
                if not HTML_FILE.exists():
                    return self.send_json({
                        "ok": False,
                        "error": "Falta index.html"
                    }, 404)

                content = HTML_FILE.read_bytes()

                self.send_response(200)
                self.send_header(
                    "Content-Type", "text/html; charset=utf-8"
                )
                self.send_header(
                    "Content-Length", str(len(content))
                )
                self.end_headers()
                self.wfile.write(content)

            else:
                self.send_json({
                    "ok": False,
                    "error": "Ruta no encontrada"
                }, 404)

        except Exception as exc:
            self.send_json({
                "ok": False,
                "error": str(exc)
            }, 500)

    def do_POST(self):
        global scan_running, scan_error

        if self.path != "/api/scan":
            return self.send_json({
                "ok": False,
                "error": "Ruta no encontrada"
            }, 404)

        with lock:
            if scan_running:
                return self.send_json({
                    "ok": False,
                    "error": "Ya hay un escaneo en ejecución"
                }, 409)

            scan_running = True
            scan_error = None

        threading.Thread(
            target=start_scan,
            daemon=True
        ).start()

        self.send_json({
            "ok": True,
            "message": "Escaneo iniciado"
        }, 202)


if __name__ == "__main__":
    print("Cleaner AntiRAT iniciado")
    print(f"Abre http://{HOST}:{PORT}")

    HTTPServer((HOST, PORT), CleanerHandler).serve_forever()
