from rest_framework import serializers

from .models import Driver


class DriverVerificationSerializer(serializers.ModelSerializer):
    fullName = serializers.CharField(source='full_name')
    nidaNumber = serializers.CharField(source='nida_number')
    carName = serializers.CharField(source='car_name')
    plateNumber = serializers.CharField(source='plate_number')
    carType = serializers.ChoiceField(source='car_type', choices=Driver.CAR_TYPES)
    numberOfSeats = serializers.IntegerField(source='number_of_seats', min_value=2, max_value=7)
    profilePhoto = serializers.ImageField(source='profile_photo')
    idPhoto = serializers.ImageField(source='id_photo')
    carPhoto = serializers.ImageField(source='car_photo')

    class Meta:
        model = Driver
        fields = [
            'fullName',
            'nidaNumber',
            'address',
            'carName',
            'plateNumber',
            'carType',
            'numberOfSeats',
            'profilePhoto',
            'idPhoto',
            'carPhoto',
        ]
        read_only_fields = []

    def create(self, validated_data):
        user = self.context['request'].user
        validated_data['user'] = user
        return super().create(validated_data)