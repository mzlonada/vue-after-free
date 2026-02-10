#!/usr/bin/env python3
"""Send inject.js to PS4 for execution"""

import argparse
import asyncio
import pathlib
import readline  # noqa: F401
from datetime import datetime

import websockets

parser = argparse.ArgumentParser(description="WebSocket client for JSMAF")
parser.add_argument("ip", help="IP address of the PS4")
parser.add_argument(
    "-p", "--port", type=int, default=40404, help="Port number (default: 40404)"
)
parser.add_argument("-d", "--delay", type=int, default=2, help="Delay (default: 2)")

args = parser.parse_args()

IP = args.ip
PORT = args.port
DELAY = args.delay
RETRY = True


def log_print(message: str) -> None:
    time_now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{time_now}] {message}")


async def send_file(ws: websockets.ClientConnection, file_path: str) -> None:
    try:
        path = pathlib.Path(file_path)
        if not path.is_file():
            log_print(f"[!] File not found: {file_path}")
            return

        message = path.read_text("utf-8")
        await ws.send(message)

        log_print(f"[*] Sent {file_path} ({len(message)} bytes) to server")
    except Exception as e:
        log_print(f"[!] Failed to send file: {e}")


async def command(ws: websockets.ClientConnection) -> None:
    global RETRY

    loop = asyncio.get_event_loop()
    while ws.state == websockets.protocol.State.OPEN:
        try:
            cmd = await loop.run_in_executor(None, input, ">")
        except (EOFError, KeyboardInterrupt):
            print()
            log_print("[*] Disconnecting...")
            await ws.close()
            RETRY = False
            break

        parts = cmd.split(maxsplit=1)

        if len(parts) == 2 and parts[0].lower() == "send":
            await send_file(ws, parts[1])
        elif cmd.lower() in ("quit", "exit", "disconnect"):
            log_print("[*] Disconnecting...")
            await ws.close()
            RETRY = False
            break
        else:
            log_print("[*] Unknown command. Use: send <path-to-file>")


async def receiver(ws: websockets.ClientConnection) -> None:
    try:
        async for data in ws:
            if isinstance(data, str):
                log_print(data)
    except websockets.ConnectionClosed:
        log_print("[*] Disconnected")
        pass
    except Exception as e:
        log_print(f"[!] {e}")


async def main() -> None:
    while RETRY:
        ws = None
        receiver_task = None
        command_task = None
        try:
            # log_print(f"[*] Connecting to {IP}:{PORT}...")
            async with websockets.connect(f"ws://{IP}:{PORT}", ping_timeout=None) as ws:
                log_print(f"[*] Connected to {IP}:{PORT} !!")
                receiver_task = asyncio.create_task(receiver(ws))
                command_task = asyncio.create_task(command(ws))

                await asyncio.wait(
                    [receiver_task, command_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
        except Exception as e:
            # log_print(f"[!] Error: {e}")
            # log_print(f"[*] Retrying in {DELAY} seconds...")
            await asyncio.sleep(DELAY)
        finally:
            if receiver_task is not None:
                receiver_task.cancel()
            if command_task is not None:
                command_task.cancel()
            if ws is not None and ws.state != websockets.protocol.State.CLOSED:
                await ws.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
