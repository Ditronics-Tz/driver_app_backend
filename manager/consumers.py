from urllib.parse import parse_qs

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from rest_framework_simplejwt.authentication import JWTAuthentication


class AdminBroadcastConsumer(AsyncJsonWebsocketConsumer):
    group_prefix = "admin"

    async def connect(self):
        token = self._get_token()
        if not token:
            await self.close()
            return
        if token.get("user_type") != "admin":
            await self.close()
            return
        channel = self.scope["url_route"]["kwargs"].get("channel")
        group_name = f"{self.group_prefix}.{channel}"
        await self.channel_layer.group_add(group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        channel = self.scope["url_route"]["kwargs"].get("channel")
        group_name = f"{self.group_prefix}.{channel}"
        await self.channel_layer.group_discard(group_name, self.channel_name)

    async def broadcast(self, event):
        await self.send_json(event.get("payload", {}))

    def _get_token(self):
        query_string = self.scope.get("query_string", b"").decode()
        params = parse_qs(query_string)
        raw_token = params.get("token", [None])[0]
        if not raw_token:
            return None
        authenticator = JWTAuthentication()
        return authenticator.get_validated_token(raw_token)


class TicketConsumer(AdminBroadcastConsumer):
    group_prefix = "ticket"


class DriverLocationConsumer(AdminBroadcastConsumer):
    group_prefix = "driver"


class SosAlertConsumer(AdminBroadcastConsumer):
    group_prefix = "sos"
