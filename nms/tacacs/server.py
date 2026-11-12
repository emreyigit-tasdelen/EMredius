# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Enterprise TACACS+ RFC 8907 Asynchronous TCP Server Daemon.

Handles TCP connection lifecycle, single-connection multiplexing,
session tracking, multi-client secret lookup, and WAL heartbeats.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from nms.common.db import get_db_connection
from nms.tacacs.acct import handle_acct_packet
from nms.tacacs.authen import handle_authen_packet
from nms.tacacs.author import handle_author_packet
from nms.tacacs.codec import (
    TAC_PLUS_ACCT,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_SINGLE_CONNECT_FLAG,
    TAC_PLUS_UNENCRYPTED_FLAG,
    TacacsHeader,
    unpack_header,
)
from nms.tacacs.crypto import decrypt_body, encrypt_body

logger = logging.getLogger("tacacs.server")
MAX_PACKET_LENGTH = 65536  # 64 KB safety threshold


@dataclass
class ClientProfile:
    id: int
    name: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    shared_secret: str
    vendor: str
    is_active: bool


@dataclass
class TacacsSession:
    session_id: int
    client_ip: str
    authen_type: int = 0
    authen_service: int = 1
    priv_lvl: int = 1
    username: str = ""
    state: str = "INIT"
    expected_seq: int = 1
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)


class ClientSecretResolver:
    """Subnet/CIDR Longest-Prefix-Match (LPM) resolver for NAS clients."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._profiles: List[ClientProfile] = []
        self._ip_cache: Dict[str, Optional[ClientProfile]] = {}
        self.reload()

    def reload(self) -> None:
        """Loads client definitions from DB and sorts by prefix length desc."""
        profiles = []
        try:
            with get_db_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, name, ip_cidr, shared_secret, vendor, is_active "
                    "FROM tacacs_clients WHERE is_active = 1"
                )
                for row in cursor.fetchall():
                    cid, name, ip_cidr, secret, vendor, active = (
                        row["id"],
                        row["name"],
                        row["ip_cidr"],
                        row["shared_secret"],
                        row["vendor"],
                        row["is_active"],
                    )
                    net = ipaddress.ip_network(ip_cidr.strip(), strict=False)
                    profiles.append(
                        ClientProfile(
                            id=cid,
                            name=name,
                            network=net,
                            shared_secret=secret,
                            vendor=vendor or "cisco",
                            is_active=bool(active),
                        )
                    )
        except Exception as e:
            logger.error(f"Error loading tacacs_clients: {e}")
            default_net = ipaddress.ip_network("127.0.0.1/32")
            profiles.append(
                ClientProfile(0, "default-localhost", default_net, "testing123", "cisco", True)
            )

        # Sort: Highest prefixlen first (LPM), then lowest ID
        profiles.sort(key=lambda p: (p.network.prefixlen, -p.id), reverse=True)
        self._profiles = profiles
        self._ip_cache.clear()
        logger.info(f"Loaded {len(self._profiles)} active TACACS+ client profiles.")

    def resolve(self, client_ip: str) -> Optional[ClientProfile]:
        """Resolves ClientProfile by IP using LPM with fast caching."""
        if client_ip in self._ip_cache:
            return self._ip_cache[client_ip]

        try:
            ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            self._ip_cache[client_ip] = None
            return None

        matched_profile: Optional[ClientProfile] = None
        for profile in self._profiles:
            if ip_obj.version == profile.network.version and ip_obj in profile.network:
                matched_profile = profile
                break

        self._ip_cache[client_ip] = matched_profile
        return matched_profile


class TacacsServer:
    """Async TACACS+ RFC 8907 Daemon."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 49,
        fallback_port: int = 4949,
        allow_port_fallback: bool = True,
        db_path: str = "data/enterprise_nms.db",
        idle_timeout: float = 60.0,
        single_connect_timeout: float = 300.0,
    ):
        self.host = host
        self.port = port
        self.fallback_port = fallback_port
        self.allow_port_fallback = allow_port_fallback
        self.db_path = db_path
        self.idle_timeout = idle_timeout
        self.single_connect_timeout = single_connect_timeout

        self.resolver = ClientSecretResolver(db_path)
        self.server: Optional[asyncio.Server] = None
        self._shutting_down = False
        self.start_time = time.time()

        self.sessions: Dict[Tuple[str, int], TacacsSession] = {}
        self.active_tasks: Set[asyncio.Task] = set()

        self.metrics = {
            "total_connections": 0,
            "total_authen_requests": 0,
            "total_author_requests": 0,
            "total_acct_requests": 0,
            "total_errors": 0,
        }

    async def start(self) -> None:
        """Binds TCP socket and launches background workers."""
        try:
            self.server = await asyncio.start_server(
                self._handle_connection,
                host=self.host,
                port=self.port,
                reuse_address=True,
            )
            logger.info(f"TACACS+ server listening on {self.host}:{self.port}")
        except (PermissionError, OSError) as e:
            if self.allow_port_fallback and self.port != self.fallback_port:
                logger.warning(
                    f"Binding to port {self.port} failed ({e}). "
                    f"Falling back to unprivileged port {self.fallback_port}..."
                )
                self.port = self.fallback_port
                self.server = await asyncio.start_server(
                    self._handle_connection,
                    host=self.host,
                    port=self.port,
                    reuse_address=True,
                )
                logger.info(f"TACACS+ server listening on fallback {self.host}:{self.port}")
            else:
                raise

        # Launch background tasks
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._reaper_task = asyncio.create_task(self._session_reaper_loop())

    async def stop(self) -> None:
        """Performs graceful shutdown of server and active connections."""
        self._shutting_down = True
        logger.info("Stopping TACACS+ server...")

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        background_tasks = []
        if hasattr(self, "_heartbeat_task"):
            self._heartbeat_task.cancel()
            background_tasks.append(self._heartbeat_task)
        if hasattr(self, "_reaper_task"):
            self._reaper_task.cancel()
            background_tasks.append(self._reaper_task)
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)

        if self.active_tasks:
            for task in list(self.active_tasks):
                task.cancel()
            await asyncio.gather(*self.active_tasks, return_exceptions=True)

        try:
            await self._write_heartbeat(status="STOPPED")
        except Exception:
            pass
        logger.info("TACACS+ server stopped successfully.")

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        current_task = asyncio.current_task()
        if current_task:
            self.active_tasks.add(current_task)

        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "unknown"
        client_port = peer[1] if peer else 0
        self.metrics["total_connections"] += 1

        client_profile = self.resolver.resolve(client_ip)
        if not client_profile:
            logger.warning(f"Connection from unrecognized client {client_ip}:{client_port}. Dropping.")
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if current_task:
                self.active_tasks.discard(current_task)
            return

        shared_secret = client_profile.shared_secret
        single_connect_enabled = False
        conn_sessions: Set[int] = set()

        try:
            while not self._shutting_down:
                current_timeout = (
                    self.single_connect_timeout if single_connect_enabled else self.idle_timeout
                )
                try:
                    header_bytes = await asyncio.wait_for(
                        reader.readexactly(12), timeout=current_timeout
                    )
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    break
                except asyncio.TimeoutError:
                    break

                header = unpack_header(header_bytes)

                if header.major_version != TAC_PLUS_MAJOR_VER:
                    logger.error(f"Invalid major version {header.major_version} from {client_ip}")
                    break

                if header.flags & TAC_PLUS_UNENCRYPTED_FLAG:
                    logger.error(f"Insecure unencrypted packet received from {client_ip}. Dropping.")
                    break

                if header.length > MAX_PACKET_LENGTH:
                    logger.error(f"Packet length {header.length} exceeds limit from {client_ip}")
                    break

                body_bytes = b""
                if header.length > 0:
                    try:
                        body_bytes = await asyncio.wait_for(
                            reader.readexactly(header.length), timeout=10.0
                        )
                    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                        break

                if header.seq_no == 1 and (header.flags & TAC_PLUS_SINGLE_CONNECT_FLAG):
                    single_connect_enabled = True

                plain_body = decrypt_body(
                    header=header,
                    encrypted_body=body_bytes,
                    secret=shared_secret,
                )
                if plain_body is None:
                    logger.error(f"Decryption integrity check failed for {client_ip}")
                    self.metrics["total_errors"] += 1
                    break

                conn_sessions.add(header.session_id)
                session_key = (client_ip, header.session_id)
                session = self.sessions.setdefault(
                    session_key,
                    TacacsSession(session_id=header.session_id, client_ip=client_ip),
                )
                session.last_activity = time.time()

                resp_header, resp_body, is_terminal = await self._dispatch_packet(
                    header=header,
                    plain_body=plain_body,
                    session=session,
                    client_profile=client_profile,
                    single_connect_enabled=single_connect_enabled,
                )

                if resp_header and resp_body is not None:
                    if single_connect_enabled and resp_header.seq_no == 2:
                        resp_header.flags |= TAC_PLUS_SINGLE_CONNECT_FLAG

                    enc_body = encrypt_body(
                        header=resp_header,
                        plain_body=resp_body,
                        secret=shared_secret,
                    )
                    resp_header.length = len(enc_body)
                    raw_resp = resp_header.pack() + enc_body

                    writer.write(raw_resp)
                    await asyncio.wait_for(writer.drain(), timeout=5.0)

                if is_terminal:
                    self.sessions.pop(session_key, None)
                    conn_sessions.discard(header.session_id)
                    if not single_connect_enabled:
                        break

        except Exception as e:
            logger.error(f"Error handling connection from {client_ip}: {e}", exc_info=True)
            self.metrics["total_errors"] += 1
        finally:
            for sid in conn_sessions:
                self.sessions.pop((client_ip, sid), None)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if current_task:
                self.active_tasks.discard(current_task)

    async def _dispatch_packet(
        self,
        header: TacacsHeader,
        plain_body: bytes,
        session: TacacsSession,
        client_profile: ClientProfile,
        single_connect_enabled: bool,
    ) -> Tuple[Optional[TacacsHeader], Optional[bytes], bool]:
        """Routes packet to Authen, Author, or Acct handler."""
        if header.type == TAC_PLUS_AUTHEN:
            self.metrics["total_authen_requests"] += 1
            return await handle_authen_packet(header, plain_body, session, self.db_path)
        elif header.type == TAC_PLUS_AUTHOR:
            self.metrics["total_author_requests"] += 1
            return await handle_author_packet(
                header, plain_body, session, client_profile, self.db_path
            )
        elif header.type == TAC_PLUS_ACCT:
            self.metrics["total_acct_requests"] += 1
            return await handle_acct_packet(
                header, plain_body, session, client_profile, self.db_path
            )
        else:
            logger.error(f"Unknown packet type {header.type}")
            return None, None, True

    async def _session_reaper_loop(self) -> None:
        """Periodically expires dead authentication sessions."""
        while not self._shutting_down:
            try:
                await asyncio.sleep(10.0)
                now = time.time()
                stale_keys = [
                    key for key, sess in self.sessions.items() if now - sess.last_activity > 30.0
                ]
                for key in stale_keys:
                    self.sessions.pop(key, None)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _heartbeat_loop(self) -> None:
        """Updates daemon_status table in SQLite WAL every 5 seconds."""
        # Initial heartbeat immediately on startup
        try:
            await self._write_heartbeat(status="RUNNING")
        except Exception as e:
            logger.error(f"Failed to write initial daemon heartbeat: {e}")

        while not self._shutting_down:
            try:
                await asyncio.sleep(5.0)
                await self._write_heartbeat(status="RUNNING")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Failed to write daemon heartbeat: {e}")

    async def _write_heartbeat(self, status: str = "RUNNING") -> None:
        payload = {
            "uptime_seconds": round(time.time() - self.start_time, 1),
            "port": self.port,
            "active_connections": len(self.active_tasks),
            "active_sessions": len(self.sessions),
            **self.metrics,
        }
        metrics_json = json.dumps(payload)
        now_iso = datetime.now(timezone.utc).isoformat()
        pid = os.getpid()

        def _db_upsert():
            with get_db_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO daemon_status (daemon_name, last_heartbeat, pid, status, metrics_json)
                    VALUES ('tacacs_daemon', ?, ?, ?, ?)
                    ON CONFLICT(daemon_name) DO UPDATE SET
                        last_heartbeat = excluded.last_heartbeat,
                        pid = excluded.pid,
                        status = excluded.status,
                        metrics_json = excluded.metrics_json
                    """,
                    (now_iso, pid, status, metrics_json),
                )
                conn.commit()

        await asyncio.to_thread(_db_upsert)
