from django.db import models

from data.models import Driver


class Ride(models.Model):
    STATUS_ACTIVE = "active"
    STATUS_COMPLETED = "completed"
    STATUS_CANCELLED = "cancelled"

    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_CANCELLED, "Cancelled"),
    ]

    driver = models.ForeignKey(Driver, on_delete=models.SET_NULL, null=True, blank=True, related_name="rides")
    passenger = models.ForeignKey("authentication.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="rides")
    start_lat = models.FloatField()
    start_lng = models.FloatField()
    start_address = models.CharField(max_length=255, blank=True)
    end_lat = models.FloatField()
    end_lng = models.FloatField()
    end_address = models.CharField(max_length=255, blank=True)
    distance_km = models.FloatField()
    duration_min = models.FloatField()
    geometry = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancel_reason = models.TextField(blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return (
            f"Ride {self.id} from ({self.start_lat}, {self.start_lng}) "
            f"to ({self.end_lat}, {self.end_lng})"
        )
