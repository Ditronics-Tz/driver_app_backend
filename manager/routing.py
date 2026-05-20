from django.urls import re_path

from . import consumers


websocket_urlpatterns = [
    re_path(r"^ws/admin/(?P<channel>alerts|dashboard)/$", consumers.AdminBroadcastConsumer.as_asgi()),
    re_path(r"^ws/admin/ticket/(?P<channel>\\d+)/$", consumers.TicketConsumer.as_asgi()),
    re_path(r"^ws/admin/driver/(?P<channel>location)/$", consumers.DriverLocationConsumer.as_asgi()),
    re_path(r"^ws/admin/sos/(?P<channel>alerts)/$", consumers.SosAlertConsumer.as_asgi()),
]
