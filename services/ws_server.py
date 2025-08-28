import asyncio
import json
import websockets

class WebSocketServer:
    def __init__(self, host="0.0.0.0", port=8765):
        self.host = host
        self.port = port
        self.clients = set()
        self.on_message_callback = None

    async def _handle_connection(self, ws):
        self.clients.add(ws)
        try:
            async for msg in ws:
                try:
                    data = json.loads(msg)
                except json.JSONDecodeError:
                    await ws.send(json.dumps({"type": "error", "message": "Invalid JSON"}))
                    continue

                if self.on_message_callback:
                    if asyncio.iscoroutinefunction(self.on_message_callback):
                        await self.on_message_callback(ws, data)
                    else:
                        self.on_message_callback(ws, data)
        except websockets.exceptions.ConnectionClosedOK:
            pass
        finally:
            self.clients.discard(ws)

    def set_message_handler(self, callback):
        """Set the async callback to handle incoming messages."""
        self.on_message_callback = callback

    async def send_to_client(self, ws, message: dict):
        """Send a message to a specific client."""
        await ws.send(json.dumps(message))

    async def broadcast(self, message: dict):
        """Send a message to all connected clients."""
        for ws in self.clients:
            await ws.send(json.dumps(message))

    async def start(self):
        """Start the WebSocket server."""
        async with websockets.serve(self._handle_connection, self.host, self.port):
            print(f"WebSocket server running at ws://{self.host}:{self.port}")
            await asyncio.Future()