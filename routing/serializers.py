from rest_framework import serializers

from .models import Ride


class RideSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ride
        fields = [
            "id",
            "driver",
            "passenger",
            "start_lat",
            "start_lng",
            "start_address",
            "end_lat",
            "end_lng",
            "end_address",
            "distance_km",
            "duration_min",
            "geometry",
            "created_at",
            "status",
            "cancelled_at",
            "cancel_reason",
            "completed_at",
        ]
        read_only_fields = [
            "id",
            "distance_km",
            "duration_min",
            "geometry",
            "created_at",
            "cancelled_at",
            "completed_at",
        ]
