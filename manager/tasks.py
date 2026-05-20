from datetime import timedelta
import csv
import io

from celery import shared_task
from django.utils import timezone
from django.db import models
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from .models import (
    DailyRevenue,
    DailyRideStats,
    PaymentTransaction,
    Ride,
    Alert,
    Notification,
    PayoutRequest,
    Refund,
    SupportTicket,
    AnalyticsExportJob,
)
from data.models import Driver
from authentication.models import User


@shared_task
def aggregate_daily_revenue():
    today = timezone.now().date() - timedelta(days=1)
    total = PaymentTransaction.objects.filter(
        status=PaymentTransaction.STATUS_SUCCESS,
        created_at__date=today,
    ).aggregate(total_amount=models.Sum("amount")).get("total_amount") or 0
    DailyRevenue.objects.update_or_create(date=today, defaults={"total_amount": total})


@shared_task
def aggregate_daily_rides():
    today = timezone.now().date() - timedelta(days=1)
    completed = Ride.objects.filter(status=Ride.STATUS_COMPLETED, created_at__date=today).count()
    cancelled = Ride.objects.filter(status=Ride.STATUS_CANCELLED, created_at__date=today).count()
    DailyRideStats.objects.update_or_create(
        date=today,
        defaults={"completed": completed, "cancelled": cancelled},
    )


@shared_task
def detect_fraud_patterns():
    # Placeholder: flag rides cancelled frequently in the last hour.
    threshold = 10
    recent_cancelled = Ride.objects.filter(
        status=Ride.STATUS_CANCELLED,
        cancelled_at__gte=timezone.now() - timedelta(hours=1),
    ).count()
    if recent_cancelled >= threshold:
        Alert.objects.create(
            type=Alert.TYPE_FRAUD,
            severity=Alert.SEVERITY_WARNING,
            description="High cancellation volume detected.",
            linked_entity_type="system",
            linked_entity_id="cancellation-spike",
        )


@shared_task
def send_scheduled_notification(notification_id):
    notification = Notification.objects.filter(id=notification_id, status=Notification.STATUS_PENDING).first()
    if not notification:
        return
    notification.status = Notification.STATUS_SENT
    notification.sent_at = timezone.now()
    notification.save(update_fields=["status", "sent_at"])


@shared_task
def process_payout(payout_id):
    payout = PayoutRequest.objects.filter(id=payout_id, status=PayoutRequest.STATUS_PENDING).first()
    if not payout:
        return
    payout.status = PayoutRequest.STATUS_APPROVED
    payout.approved_at = timezone.now()
    payout.save(update_fields=["status", "approved_at"])


@shared_task
def process_refund(refund_id):
    refund = Refund.objects.filter(id=refund_id, status=Refund.STATUS_PENDING).first()
    if not refund:
        return
    refund.status = Refund.STATUS_APPROVED
    refund.approved_at = timezone.now()
    refund.save(update_fields=["status", "approved_at"])


@shared_task
def close_stale_tickets():
    cutoff = timezone.now() - timedelta(days=7)
    stale = SupportTicket.objects.filter(status=SupportTicket.STATUS_RESOLVED, updated_at__lt=cutoff)
    stale.update(status=SupportTicket.STATUS_CLOSED)


@shared_task
def send_dashboard_stats():
    active_rides = Ride.objects.filter(status=Ride.STATUS_ACTIVE).count()
    online_drivers = Driver.objects.count()
    revenue_today = PaymentTransaction.objects.filter(
        status=PaymentTransaction.STATUS_SUCCESS,
        created_at__date=timezone.now().date(),
    ).aggregate(total=models.Sum("amount")).get("total") or 0
    new_registrations = User.objects.filter(date_joined__date=timezone.now().date()).count()
    open_tickets = SupportTicket.objects.filter(status__in=[SupportTicket.STATUS_OPEN, SupportTicket.STATUS_IN_PROGRESS]).count()
    unresolved_alerts = Alert.objects.filter(status=Alert.STATUS_ACTIVE).count()

    payload = {
        "active_rides": active_rides,
        "online_drivers": online_drivers,
        "revenue_today": revenue_today,
        "new_registrations_today": new_registrations,
        "open_ticket_count": open_tickets,
        "unresolved_alert_count": unresolved_alerts,
    }
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "admin.dashboard",
        {"type": "broadcast", "payload": payload},
    )


@shared_task
def export_report(job_id):
    job = AnalyticsExportJob.objects.filter(job_id=job_id).first()
    if not job or job.status != AnalyticsExportJob.STATUS_PENDING:
        return
    output = io.StringIO()
    writer = csv.writer(output)
    if job.report_type == "revenue":
        writer.writerow(["date", "total_amount"])
        for row in DailyRevenue.objects.order_by("date"):
            writer.writerow([row.date, row.total_amount])
    elif job.report_type == "rides":
        writer.writerow(["date", "completed", "cancelled"])
        for row in DailyRideStats.objects.order_by("date"):
            writer.writerow([row.date, row.completed, row.cancelled])
    else:
        job.status = AnalyticsExportJob.STATUS_FAILED
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "completed_at"])
        return
    job.file_content = output.getvalue()
    job.status = AnalyticsExportJob.STATUS_DONE
    job.completed_at = timezone.now()
    job.save(update_fields=["file_content", "status", "completed_at"])
