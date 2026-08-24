#!/usr/bin/env python3
"""Watchdog local de WebRTC para plataformas One Connect no Windows."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

BASE_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
WINDOWS = platform.system() == "Windows"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
LOG = logging.getLogger("oneconnect.watchdog")
DEFAULT_CONFIG = {
    "hosts": ["app.oneconnect.med.br", "cori.oneconnect.med.br", "telelaudo.oneconnect.med.br"],
    "initial_url": "https://app.oneconnect.med.br",
    "chrome_debug_port": 9222,
    "edge_debug_port": 9223,
    "poll_interval_seconds": 3,
    "startup_grace_seconds": 4,
    "persistent_failure_seconds": 15,
    "page_latency_threshold_ms": 1000,
    "webrtc_rtt_threshold_ms": 1000,
    "webrtc_jitter_threshold_ms": 1000,
    "media_freeze_threshold_seconds": 15,
    "reload_grace_seconds": 15,
    "browser_restart_cooldown_seconds": 180,
    "max_browser_restarts_per_hour": 3,
    "devtools_timeout_seconds": 12,
    "network_check_timeout_seconds": 3,
    "suppress_recovery_when_host_unreachable": True,
    "start_browser_if_missing": True,
    "restart_browser_if_closed": True,
    "log_level": "INFO",
}


class LocalWebSocket:
    """Cliente RFC 6455 mínimo para DevTools local, usando apenas a biblioteca padrão."""

    def __init__(self, url: str, open_timeout: float = 10, close_timeout: float = 2) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Somente conexões WebSocket locais sem TLS são permitidas")
        self.timeout = open_timeout
        self.close_timeout = close_timeout
        self.buffer = bytearray()
        self.socket = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=open_timeout)
        self.socket.settimeout(open_timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port or 80}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.socket.sendall(request.encode("ascii"))
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = self.socket.recv(4096)
            if not chunk:
                raise ConnectionError("Servidor DevTools encerrou o handshake WebSocket")
            response.extend(chunk)
            if len(response) > 65536:
                raise ConnectionError("Resposta de handshake WebSocket excessivamente grande")
        headers_raw, remainder = response.split(b"\r\n\r\n", 1)
        self.buffer.extend(remainder)
        lines = headers_raw.decode("latin-1").split("\r\n")
        if len(lines[0].split()) < 2 or lines[0].split()[1] != "101":
            raise ConnectionError(f"Handshake WebSocket rejeitado: {lines[0]}")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if headers.get("sec-websocket-accept") != expected:
            raise ConnectionError("Handshake WebSocket possui assinatura inválida")

    def _read_exactly(self, size: int, deadline: float) -> bytes:
        while len(self.buffer) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timeout aguardando resposta WebSocket")
            self.socket.settimeout(remaining)
            try:
                chunk = self.socket.recv(max(4096, size - len(self.buffer)))
            except socket.timeout as exc:
                raise TimeoutError("Timeout aguardando resposta WebSocket") from exc
            if not chunk:
                raise ConnectionError("Conexão WebSocket encerrada")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        mask = os.urandom(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.socket.sendall(bytes(header) + mask + masked)

    def send(self, value: str) -> None:
        self._send_frame(0x1, value.encode("utf-8"))

    def recv(self, timeout: float | None = None) -> str:
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        fragments = bytearray()
        while True:
            first, second = self._read_exactly(2, deadline)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exactly(2, deadline))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exactly(8, deadline))[0]
            if length > 8_000_000:
                raise ConnectionError("Mensagem WebSocket excedeu o limite de segurança")
            mask = self._read_exactly(4, deadline) if masked else None
            payload = self._read_exactly(length, deadline)
            if mask:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if opcode == 0x8:
                raise ConnectionError("Servidor DevTools encerrou a conexão")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode not in {0x0, 0x1}:
                raise ConnectionError(f"Tipo de mensagem WebSocket não suportado: {opcode}")
            fragments.extend(payload)
            if final:
                return fragments.decode("utf-8")

    def close(self) -> None:
        try:
            self.socket.settimeout(self.close_timeout)
            self._send_frame(0x8, b"")
        except OSError:
            pass
        finally:
            self.socket.close()

    def __enter__(self) -> LocalWebSocket:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


connect = LocalWebSocket


INSTRUMENT_SCRIPT = r"""
(() => {
  const key = Symbol.for('oneconnect.watchdog.peerConnections');
  if (!Array.isArray(window[key])) window[key] = [];
  if (window.__oneconnectWatchdogInstalled) return;
  window.__oneconnectWatchdogInstalled = true;
  const NativePeerConnection = window.RTCPeerConnection;
  if (typeof NativePeerConnection !== 'function') return;

  try {
    for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(window))) {
      if ('value' in descriptor && descriptor.value instanceof NativePeerConnection) {
        if (!window[key].includes(descriptor.value)) window[key].push(descriptor.value);
      }
    }
  } catch (_) {}

  const instrumented = new Proxy(NativePeerConnection, {
    construct(target, args, newTarget) {
      const connection = Reflect.construct(target, args, newTarget);
      window[key].push(connection);
      return connection;
    }
  });
  try {
    window.RTCPeerConnection = instrumented;
    if (window.webkitRTCPeerConnection === NativePeerConnection) {
      window.webkitRTCPeerConnection = instrumented;
    }
  } catch (_) {}
})();
"""


COLLECT_SCRIPT = r"""
(async () => {
  const key = Symbol.for('oneconnect.watchdog.peerConnections');
  const peers = Array.isArray(window[key]) ? window[key] : [];
  const visibleText = document.body ? document.body.innerText.slice(0, 150000) : '';
  const rawMatches = visibleText.match(/(?:\d{1,3}(?:[.,]\d{3})+|\d{1,9})(?:[.,]\d+)?\s*ms\b/gi) || [];

  function parseMs(raw) {
    let value = raw.toLowerCase().replace(/\s*ms\s*$/, '').trim();
    if (/^\d{1,3}(?:[.,]\d{3})+$/.test(value)) value = value.replace(/[.,]/g, '');
    else if (value.includes(',') && value.includes('.')) {
      const decimal = Math.max(value.lastIndexOf(','), value.lastIndexOf('.'));
      value = value.slice(0, decimal).replace(/[.,]/g, '') + '.' + value.slice(decimal + 1);
    } else value = value.replace(',', '.');
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  const result = {
    url: location.href,
    title: document.title,
    visibility: document.visibilityState,
    page_ms: rawMatches.map(parseMs).filter(value => value !== null),
    peer_count: peers.length,
    peer_states: [],
    rtt_ms: [],
    jitter_ms: [],
    inbound_bytes: 0,
    inbound_packets: 0,
    frames_decoded: 0,
    inbound_tracks: 0,
    stats_errors: 0
  };

  for (const peer of peers.slice(-20)) {
    result.peer_states.push({
      connection: peer.connectionState || 'unknown',
      ice: peer.iceConnectionState || 'unknown'
    });
    if (peer.connectionState === 'closed') continue;
    let reports;
    try {
      reports = await Promise.race([
        peer.getStats(),
        new Promise((_, reject) => setTimeout(() => reject(Error('getStats timeout')), 1600))
      ]);
    } catch (_) {
      result.stats_errors += 1;
      continue;
    }

    reports.forEach(report => {
      if (report.type === 'candidate-pair' && report.state === 'succeeded') {
        if (typeof report.currentRoundTripTime === 'number') {
          result.rtt_ms.push(report.currentRoundTripTime * 1000);
        }
      }
      if (report.type === 'remote-inbound-rtp' && typeof report.roundTripTime === 'number') {
        result.rtt_ms.push(report.roundTripTime * 1000);
      }
      if (report.type === 'inbound-rtp') {
        result.inbound_tracks += 1;
        result.inbound_bytes += Number(report.bytesReceived || 0);
        result.inbound_packets += Number(report.packetsReceived || 0);
        result.frames_decoded += Number(report.framesDecoded || 0);
        if (typeof report.jitter === 'number') result.jitter_ms.push(report.jitter * 1000);
      }
    });
  }
  return result;
})()
"""


@dataclass
class BrowserSpec:
    name: str
    process: str
    port: int
    profile: Path


@dataclass
class TabState:
    failures: int = 0
    bad_since: float | None = None
    reload_at: float | None = None
    previous_bytes: int | None = None
    previous_packets: int | None = None
    previous_frames: int | None = None
    last_media_progress: float | None = None
    last_sample: dict[str, Any] = field(default_factory=dict)


class DevToolsError(RuntimeError):
    """Falha na comunicação local com Chrome DevTools Protocol."""


class DevToolsSession:
    def __init__(self, websocket_url: str, timeout: float) -> None:
        self.timeout = timeout
        self.counter = 0
        self.connection = connect(websocket_url, open_timeout=timeout, close_timeout=2)
        self.call("Page.enable")
        self.call("Runtime.enable")
        self.call("Page.addScriptToEvaluateOnNewDocument", {"source": INSTRUMENT_SCRIPT})
        self.call("Runtime.evaluate", {"expression": INSTRUMENT_SCRIPT})

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.counter += 1
        request_id = self.counter
        self.connection.send(json.dumps({"id": request_id, "method": method, "params": params or {}}))
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DevToolsError(f"Timeout executando {method}")
            response = json.loads(self.connection.recv(timeout=remaining))
            if response.get("id") != request_id:
                continue
            if "error" in response:
                raise DevToolsError(f"{method}: {response['error']}")
            return response.get("result", {})

    def sample(self) -> dict[str, Any]:
        response = self.call(
            "Runtime.evaluate",
            {"expression": COLLECT_SCRIPT, "awaitPromise": True, "returnByValue": True},
        )
        if "exceptionDetails" in response:
            raise DevToolsError(str(response["exceptionDetails"]))
        value = response.get("result", {}).get("value")
        if not isinstance(value, dict):
            raise DevToolsError("A página não retornou estatísticas válidas")
        return value

    def reload(self) -> None:
        self.call("Page.reload", {"ignoreCache": True})

    def close(self) -> None:
        try:
            self.connection.close()
        except Exception:
            pass


def load_config() -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    config["hosts"] = list(DEFAULT_CONFIG["hosts"])
    hosts = config.get("hosts", [])
    if not hosts or not all(isinstance(host, str) for host in hosts):
        raise ValueError("A configuração precisa conter uma lista de hosts")
    if config.get("persistent_failure_seconds", 0) <= 0:
        raise ValueError("persistent_failure_seconds precisa ser maior que zero")
    if config.get("poll_interval_seconds", 0) <= 0:
        raise ValueError("poll_interval_seconds precisa ser maior que zero")
    return config


def configure_logging(config: dict[str, Any]) -> None:
    local = Path(os.environ.get("LOCALAPPDATA", str(BASE_DIR)))
    log_dir = local / "OneConnectWatchdog" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s")
    disk = RotatingFileHandler(log_dir / "oneconnect-watchdog.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    disk.setFormatter(formatter)
    LOG.setLevel(getattr(logging, str(config.get("log_level", "INFO")).upper(), logging.INFO))
    LOG.handlers.clear()
    LOG.addHandler(disk)
    if sys.stdout is not None:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        LOG.addHandler(console)


def is_monitored_url(url: str, hosts: list[str]) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and (parsed.hostname or "").lower() in {host.lower() for host in hosts}


def browser_specs(config: dict[str, Any]) -> dict[str, BrowserSpec]:
    local = Path(os.environ.get("LOCALAPPDATA", str(BASE_DIR / "profiles")))
    root = local / "OneConnectWatchdog"
    return {
        "chrome": BrowserSpec("chrome", "chrome.exe", int(config.get("chrome_debug_port", 9222)), root / "ChromeProfile"),
        "edge": BrowserSpec("edge", "msedge.exe", int(config.get("edge_debug_port", 9223)), root / "EdgeProfile"),
    }


def json_endpoint(port: int, suffix: str, timeout: float = 3) -> Any:
    request = Request(f"http://127.0.0.1:{port}/{suffix.lstrip('/')}", headers={"Host": f"127.0.0.1:{port}"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def discover_tabs(spec: BrowserSpec, hosts: list[str]) -> list[dict[str, Any]]:
    try:
        targets = json_endpoint(spec.port, "json/list")
    except (URLError, OSError, ValueError, TimeoutError):
        return []
    return [
        target for target in targets
        if target.get("type") == "page"
        and target.get("webSocketDebuggerUrl")
        and is_monitored_url(target.get("url", ""), hosts)
    ]


def endpoint_available(spec: BrowserSpec) -> bool:
    try:
        response = json_endpoint(spec.port, "json/version")
        return isinstance(response, dict) and "Browser" in response
    except (URLError, OSError, ValueError, TimeoutError):
        return False


def running_process(name: str) -> bool:
    if not WINDOWS:
        return False
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=8, creationflags=CREATE_NO_WINDOW,
        )
        return f'"{name.lower()}"' in result.stdout.lower()
    except (OSError, subprocess.SubprocessError):
        return False


def locate_browser(name: str) -> str:
    suffixes = {
        "chrome": [r"Google\Chrome\Application\chrome.exe"],
        "edge": [r"Microsoft\Edge\Application\msedge.exe"],
    }
    roots = [os.environ.get("PROGRAMFILES"), os.environ.get("PROGRAMFILES(X86)"), os.environ.get("LOCALAPPDATA")]
    for root in roots:
        if not root:
            continue
        for suffix in suffixes[name]:
            candidate = Path(root) / Path(suffix.replace("\\", os.sep))
            if candidate.is_file():
                return str(candidate)
    found = shutil.which("chrome" if name == "chrome" else "msedge")
    if found:
        return found
    raise FileNotFoundError(f"Navegador {name} não encontrado")


def choose_browser(specs: dict[str, BrowserSpec], preference: str) -> BrowserSpec:
    if preference in specs:
        return specs[preference]
    available = [spec for spec in specs.values() if endpoint_available(spec)]
    if available:
        return available[0]
    running = [spec for spec in specs.values() if running_process(spec.process)]
    if running:
        return running[0]
    for spec in specs.values():
        try:
            locate_browser(spec.name)
            return spec
        except FileNotFoundError:
            continue
    return specs["chrome"]


def start_browser(spec: BrowserSpec, urls: list[str]) -> None:
    executable = locate_browser(spec.name)
    spec.profile.mkdir(parents=True, exist_ok=True)
    arguments = [
        executable,
        f"--remote-debugging-port={spec.port}",
        "--remote-debugging-address=127.0.0.1",
        f"--user-data-dir={spec.profile}",
        "--no-first-run",
        "--no-default-browser-check",
        *dict.fromkeys(urls),
    ]
    subprocess.Popen(arguments, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
    LOG.info("Navegador %s iniciado com inspeção exclusivamente local na porta %s", spec.name, spec.port)


def listener_pid(port: int) -> int | None:
    if not WINDOWS:
        return None
    command = (
        f"$c = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort {int(port)} "
        "-State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($c) { $c.OwningProcess }"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=12, creationflags=CREATE_NO_WINDOW,
        )
        match = re.search(r"\b(\d+)\b", result.stdout)
        return int(match.group(1)) if match else None
    except (OSError, subprocess.SubprocessError):
        return None


def stop_managed_browser(spec: BrowserSpec) -> bool:
    pid = listener_pid(spec.port)
    if pid is None:
        LOG.error("Não foi possível identificar o processo gerenciado na porta %s; nenhum outro navegador será encerrado", spec.port)
        return False
    result = subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        capture_output=True, text=True, timeout=20, creationflags=CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        LOG.error("Falha ao encerrar navegador gerenciado PID %s: %s", pid, result.stderr.strip() or result.stdout.strip())
        return False
    LOG.warning("Navegador gerenciado %s encerrado; PID %s", spec.name, pid)
    return True


def endpoint_reachable(host: str, timeout: float) -> bool:
    try:
        with socket.create_connection((host, 443), timeout=timeout):
            return True
    except OSError:
        return False


def maximum(numbers: Any) -> float:
    if not isinstance(numbers, list):
        return 0.0
    values = [float(value) for value in numbers if isinstance(value, (float, int)) and not isinstance(value, bool)]
    return max(values, default=0.0)


def assess_sample(sample: dict[str, Any], state: TabState, config: dict[str, Any], now: float) -> list[str]:
    reasons: list[str] = []
    page_ms = maximum(sample.get("page_ms"))
    rtt_ms = maximum(sample.get("rtt_ms"))
    jitter_ms = maximum(sample.get("jitter_ms"))

    if page_ms >= float(config["page_latency_threshold_ms"]):
        reasons.append(f"latência visível {page_ms:.0f} ms")
    if rtt_ms >= float(config["webrtc_rtt_threshold_ms"]):
        reasons.append(f"RTT WebRTC {rtt_ms:.0f} ms")
    if jitter_ms >= float(config["webrtc_jitter_threshold_ms"]):
        reasons.append(f"jitter WebRTC {jitter_ms:.0f} ms")

    peer_states = sample.get("peer_states", [])
    if any(item.get("connection") == "failed" or item.get("ice") == "failed" for item in peer_states):
        reasons.append("conexão WebRTC/ICE em estado failed")

    active = any(
        item.get("connection") in {"connected", "connecting"} or item.get("ice") in {"connected", "completed"}
        for item in peer_states
    )
    inbound_tracks = int(sample.get("inbound_tracks", 0))
    received_bytes = int(sample.get("inbound_bytes", 0))
    packets = int(sample.get("inbound_packets", 0))
    frames = int(sample.get("frames_decoded", 0))

    if active and inbound_tracks > 0 and (received_bytes > 0 or packets > 0):
        previous = (state.previous_bytes, state.previous_packets, state.previous_frames)
        current = (received_bytes, packets, frames)
        if previous[0] is None or current != previous:
            state.last_media_progress = now
        elif state.last_media_progress is not None:
            stalled = now - state.last_media_progress
            if stalled >= float(config["media_freeze_threshold_seconds"]):
                reasons.append(f"mídia WebRTC sem progresso por {stalled:.0f} s")
        state.previous_bytes, state.previous_packets, state.previous_frames = current
    else:
        state.previous_bytes = state.previous_packets = state.previous_frames = None
        state.last_media_progress = None

    if sample.get("peer_count", 0) > 0 and sample.get("stats_errors", 0) >= sample.get("peer_count", 0):
        reasons.append("não foi possível obter estatísticas das conexões WebRTC")

    state.last_sample = sample
    return reasons


class Watchdog:
    def __init__(self, config: dict[str, Any], preference: str = "auto", dry_run: bool = False) -> None:
        self.config = config
        self.preference = preference
        self.dry_run = dry_run
        self.specs = browser_specs(config)
        self.sessions: dict[str, DevToolsSession] = {}
        self.states: dict[str, TabState] = {}
        self.restarts: deque[float] = deque()
        self.last_restart: float | None = None
        self.last_missing_browser_notice = 0.0

    def startup(self) -> None:
        if not WINDOWS:
            LOG.warning("Este agente foi projetado para Windows; inspeção remota local também pode ser testada em outros sistemas")
        spec = choose_browser(self.specs, self.preference)
        if endpoint_available(spec):
            LOG.info("Navegador %s já está disponível para monitoramento local", spec.name)
            return
        if not self.config.get("start_browser_if_missing", True):
            LOG.warning("Nenhum navegador com depuração local encontrado; aguardando inicialização manual")
            return
        LOG.info("Preparando perfil monitorado do navegador %s", spec.name)
        start_browser(spec, [self.config["initial_url"]])

    def close_sessions(self, browser_name: str | None = None) -> None:
        for target_id in list(self.sessions):
            if browser_name is None or target_id.startswith(f"{browser_name}:"):
                self.sessions.pop(target_id).close()
                self.states.pop(target_id, None)

    def restart_allowed(self, now: float) -> bool:
        cutoff = now - 3600
        while self.restarts and self.restarts[0] < cutoff:
            self.restarts.popleft()
        if len(self.restarts) >= int(self.config["max_browser_restarts_per_hour"]):
            return False
        if self.last_restart is not None and now - self.last_restart < float(self.config["browser_restart_cooldown_seconds"]):
            return False
        return True

    def restart_browser(self, spec: BrowserSpec, tabs: list[dict[str, Any]], now: float) -> None:
        if not self.restart_allowed(now):
            LOG.warning("Reinicialização bloqueada pelo limite de segurança; aguardando próxima janela")
            return
        urls = [target["url"] for target in tabs if is_monitored_url(target.get("url", ""), self.config["hosts"])]
        urls = urls or [self.config["initial_url"]]
        if self.dry_run:
            LOG.warning("SIMULAÇÃO: reiniciaria %s e restauraria %s", spec.name, urls)
            self.last_restart = now
            self.restarts.append(now)
            for target in tabs:
                self.states.pop(f"{spec.name}:{target['id']}", None)
            return
        self.close_sessions(spec.name)
        if not stop_managed_browser(spec):
            return
        time.sleep(2)
        start_browser(spec, urls)
        self.last_restart = now
        self.restarts.append(now)
        LOG.warning("Navegador %s reiniciado e páginas One Connect restauradas", spec.name)

    def handle_unhealthy(self, spec: BrowserSpec, tabs: list[dict[str, Any]], target: dict[str, Any], state: TabState, reasons: list[str], now: float) -> None:
        state.failures += 1
        if state.bad_since is None:
            state.bad_since = now
        elapsed_bad = now - state.bad_since
        required_seconds = float(self.config["persistent_failure_seconds"])
        LOG.warning(
            "%s | anormal há %.0f/%.0f s | amostra %s | %s",
            target["url"], elapsed_bad, required_seconds, state.failures, "; ".join(reasons),
        )
        if elapsed_bad < required_seconds:
            return

        host = urlparse(target["url"]).hostname or ""
        if self.config.get("suppress_recovery_when_host_unreachable", True):
            if not endpoint_reachable(host, float(self.config.get("network_check_timeout_seconds", 3))):
                LOG.warning("%s não responde na porta 443; recuperação suspensa para não reiniciar durante indisponibilidade de rede", host)
                return

        session_key = f"{spec.name}:{target['id']}"
        if state.reload_at is None:
            if self.dry_run:
                LOG.warning("SIMULAÇÃO: recarregaria a página %s", target["url"])
            else:
                self.sessions[session_key].reload()
                LOG.warning("Página recarregada como primeira tentativa: %s", target["url"])
            state.reload_at = now
            state.failures = 0
            state.bad_since = None
            state.previous_bytes = state.previous_packets = state.previous_frames = None
            state.last_media_progress = None
            return

        elapsed = now - state.reload_at
        grace = float(self.config["reload_grace_seconds"])
        if elapsed < grace:
            LOG.info("Aguardando %.0f s após recarregar a página", grace - elapsed)
            return
        LOG.error("Problema persistiu após recarregar; iniciando recuperação do navegador %s", spec.name)
        self.restart_browser(spec, tabs, now)

    def handle_inspection_failure(self, spec: BrowserSpec, tabs: list[dict[str, Any]], target: dict[str, Any], state: TabState, now: float) -> None:
        if state.bad_since is None:
            state.bad_since = now
        required_seconds = float(self.config["persistent_failure_seconds"])
        if now - state.bad_since < required_seconds:
            return
        host = urlparse(target["url"]).hostname or ""
        if self.config.get("suppress_recovery_when_host_unreachable", True):
            if not endpoint_reachable(host, float(self.config.get("network_check_timeout_seconds", 3))):
                LOG.warning("Inspeção travada, mas %s também está indisponível; recuperação suspensa", host)
                return

        if state.reload_at is None:
            if self.dry_run:
                LOG.warning("SIMULAÇÃO: recarregaria a aba sem resposta %s", target["url"])
            else:
                try:
                    with connect(target["webSocketDebuggerUrl"], open_timeout=5, close_timeout=2) as connection:
                        connection.send(json.dumps({"id": 1, "method": "Page.reload", "params": {"ignoreCache": True}}))
                    LOG.warning("Página sem resposta recebeu comando de recarregamento: %s", target["url"])
                except Exception as exc:
                    LOG.error("Não foi possível recarregar aba sem resposta: %s", exc)
                    return
            state.reload_at = now
            state.failures = 0
            state.bad_since = None
            return

        if now - state.reload_at < float(self.config["reload_grace_seconds"]):
            return
        LOG.error("Aba continua sem resposta após recarregamento; reiniciando %s", spec.name)
        self.restart_browser(spec, tabs, now)

    def inspect_target(self, spec: BrowserSpec, tabs: list[dict[str, Any]], target: dict[str, Any], now: float) -> None:
        key = f"{spec.name}:{target['id']}"
        state = self.states.setdefault(key, TabState())
        try:
            if key not in self.sessions:
                self.sessions[key] = DevToolsSession(target["webSocketDebuggerUrl"], float(self.config["devtools_timeout_seconds"]))
                LOG.info("Monitorando %s no %s; conexões WebRTC já criadas podem ficar visíveis apenas após o próximo carregamento", target["url"], spec.name)
            sample = self.sessions[key].sample()
            reasons = assess_sample(sample, state, self.config, now)
        except Exception as exc:
            LOG.warning("Falha ao inspecionar %s: %s", target.get("url"), exc)
            session = self.sessions.pop(key, None)
            if session:
                session.close()
            state.failures += 1
            if state.bad_since is None:
                state.bad_since = now
            elapsed = now - state.bad_since
            LOG.warning("Inspeção local indisponível há %.0f/%.0f s", elapsed, self.config["persistent_failure_seconds"])
            if elapsed >= float(self.config["persistent_failure_seconds"]):
                LOG.error("Inspeção local falhou persistentemente; a aba pode estar travada")
            self.handle_inspection_failure(spec, tabs, target, state, now)
            return

        if reasons:
            self.handle_unhealthy(spec, tabs, target, state, reasons, now)
            return

        if state.failures or state.reload_at is not None:
            LOG.info("Sessão recuperada: %s", target["url"])
        state.failures = 0
        state.bad_since = None
        state.reload_at = None
        LOG.debug(
            "%s | página=%.0f ms | RTT=%.0f ms | jitter=%.0f ms | peers=%s | tracks=%s",
            target["url"], maximum(sample.get("page_ms")), maximum(sample.get("rtt_ms")),
            maximum(sample.get("jitter_ms")), sample.get("peer_count", 0), sample.get("inbound_tracks", 0),
        )

    def cycle(self, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        seen: set[str] = set()
        any_browser = False
        for spec in self.specs.values():
            if self.preference != "auto" and spec.name != self.preference:
                continue
            if endpoint_available(spec):
                any_browser = True
            tabs = discover_tabs(spec, self.config["hosts"])
            for target in tabs:
                key = f"{spec.name}:{target['id']}"
                seen.add(key)
                self.inspect_target(spec, tabs, target, current)

        for key in list(self.sessions):
            if key not in seen:
                self.sessions.pop(key).close()
                self.states.pop(key, None)

        if not any_browser and current - self.last_missing_browser_notice >= 60:
            LOG.warning("Nenhum Chrome/Edge iniciado com a depuração local do agente foi encontrado")
            self.last_missing_browser_notice = current
            if self.config.get("restart_browser_if_closed", True) and not self.dry_run:
                try:
                    start_browser(choose_browser(self.specs, self.preference), [self.config["initial_url"]])
                except Exception as exc:
                    LOG.error("Não foi possível abrir o navegador monitorado: %s", exc)

    def run(self, once: bool = False) -> None:
        self.startup()
        if not once:
            time.sleep(float(self.config.get("startup_grace_seconds", 8)))
        while True:
            try:
                self.cycle()
            except Exception:
                LOG.exception("Erro inesperado em um ciclo; o agente permanecerá ativo")
            if once:
                break
            time.sleep(float(self.config["poll_interval_seconds"]))


def set_windows_startup(enabled: bool, browser: str = "auto", limit_ms: float = 1000, persistence: float = 15, interval: float = 3) -> None:
    if not WINDOWS:
        raise OSError("A inicialização automática está disponível somente no Windows")
    import winreg

    registry_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_SET_VALUE) as key:
        if not enabled:
            try:
                winreg.DeleteValue(key, "OneConnectWatchdog")
            except FileNotFoundError:
                pass
            LOG.info("Inicialização automática removida")
            return

        if getattr(sys, "frozen", False):
            command = f'"{Path(sys.executable).resolve()}"'
        else:
            pythonw = Path(sys.executable).resolve().with_name("pythonw.exe")
            interpreter = pythonw if pythonw.is_file() else Path(sys.executable).resolve()
            command = f'"{interpreter}" "{Path(__file__).resolve()}"'
        command += f" --navegador {browser} --limite-ms {limit_ms:g} --persistencia {persistence:g} --intervalo {interval:g}"
        winreg.SetValueEx(key, "OneConnectWatchdog", 0, winreg.REG_SZ, command)
        LOG.info("Inicialização automática ativada para o usuário atual")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Watchdog One Connect em arquivo único, sem dependências externas")
    parser.add_argument("--navegador", choices=["auto", "chrome", "edge"], default="auto")
    parser.add_argument("--limite-ms", type=float, default=DEFAULT_CONFIG["page_latency_threshold_ms"], help="Limite de latência/RTT/jitter em milissegundos; padrão: 1000")
    parser.add_argument("--persistencia", type=float, default=DEFAULT_CONFIG["persistent_failure_seconds"], help="Segundos consecutivos acima do limite antes de agir; padrão: 15")
    parser.add_argument("--intervalo", type=float, default=DEFAULT_CONFIG["poll_interval_seconds"], help="Intervalo de monitoramento em segundos; padrão: 3")
    startup = parser.add_mutually_exclusive_group()
    startup.add_argument("--instalar-inicializacao", action="store_true", help="Inicia automaticamente ao entrar no Windows")
    startup.add_argument("--remover-inicializacao", action="store_true", help="Remove a inicialização automática")
    parser.add_argument("--simular", action="store_true", help="Registra ações sem fechar ou recarregar páginas")
    parser.add_argument("--uma-vez", action="store_true", help="Executa somente um ciclo de monitoramento")
    args = parser.parse_args(argv)
    if args.limite_ms <= 0 or args.persistencia <= 0 or args.intervalo <= 0:
        parser.error("--limite-ms, --persistencia e --intervalo precisam ser maiores que zero")
    try:
        config = load_config()
        config.update({
            "page_latency_threshold_ms": args.limite_ms,
            "webrtc_rtt_threshold_ms": args.limite_ms,
            "webrtc_jitter_threshold_ms": args.limite_ms,
            "persistent_failure_seconds": args.persistencia,
            "poll_interval_seconds": args.intervalo,
        })
        configure_logging(config)
        if args.instalar_inicializacao or args.remover_inicializacao:
            set_windows_startup(args.instalar_inicializacao, args.navegador, args.limite_ms, args.persistencia, args.intervalo)
            return 0
        LOG.info(
            "Agente iniciado | hosts=%s | navegador=%s | limite=%.0f ms por %.0f s | simulação=%s",
            ", ".join(config["hosts"]), args.navegador, args.limite_ms, args.persistencia, args.simular,
        )
        Watchdog(config, args.navegador, args.simular).run(once=args.uma_vez)
    except KeyboardInterrupt:
        LOG.info("Agente finalizado pelo usuário")
    except Exception as exc:
        LOG.exception("Falha ao iniciar o agente: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
