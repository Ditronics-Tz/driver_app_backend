from django.contrib import admin

from .models import (
    AdminUser,
    AdminRole,
    SupportTicket,
    TicketMessage,
    Claim,
    Alert,
    AuditLog,
    Notification,
    SystemSetting,
    InternalChatThread,
    InternalChatMessage,
    PaymentTransaction,
    PayoutRequest,
    Refund,
    DailyRevenue,
    DailyRideStats,
    AnalyticsExportJob,
)

admin.site.register(AdminUser)
admin.site.register(AdminRole)
admin.site.register(SupportTicket)
admin.site.register(TicketMessage)
admin.site.register(Claim)
admin.site.register(Alert)
admin.site.register(AuditLog)
admin.site.register(Notification)
admin.site.register(SystemSetting)
admin.site.register(InternalChatThread)
admin.site.register(InternalChatMessage)
admin.site.register(PaymentTransaction)
admin.site.register(PayoutRequest)
admin.site.register(Refund)
admin.site.register(DailyRevenue)
admin.site.register(DailyRideStats)
admin.site.register(AnalyticsExportJob)
