import json
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Driver
from .serializers import DriverVerificationSerializer

User = get_user_model()

SMALL_GIF = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01\x04\x00;'


class DriverModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_driver_creation(self):
        driver = Driver.objects.create(
            user=self.user,
            full_name='John Doe',
            nida_number='1234567890123456',
            address='123 Main St, Dar es Salaam',
            car_name='Toyota Corolla',
            plate_number='T123ABC',
            car_type='Sedan',
            number_of_seats=4
        )
        self.assertEqual(driver.full_name, 'John Doe')
        self.assertEqual(driver.status, 'pending')
        self.assertIsNotNone(driver.submitted_at)

    def test_driver_str(self):
        driver = Driver.objects.create(
            user=self.user,
            full_name='Jane Doe',
            nida_number='9876543210987654',
            address='456 Elm St',
            car_name='Honda Civic',
            plate_number='T456DEF',
            car_type='Sedan',
            number_of_seats=4
        )
        self.assertEqual(str(driver), f"Driver Jane Doe ({self.user})")


class DriverVerificationSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='serializeruser',
            email='serializer@example.com',
            password='testpass123'
        )

    def test_serializer_valid_data(self):
        data = {
            'fullName': 'John Doe',
            'nidaNumber': '1234567890123456',
            'address': '123 Main St',
            'carName': 'Toyota Corolla',
            'plateNumber': 'T123ABC',
            'carType': 'Sedan',
            'numberOfSeats': 4,
            'profilePhoto': SimpleUploadedFile("profile.gif", SMALL_GIF, content_type="image/gif"),
            'idPhoto': SimpleUploadedFile("id.gif", SMALL_GIF, content_type="image/gif"),
            'carPhoto': SimpleUploadedFile("car.gif", SMALL_GIF, content_type="image/gif"),
        }
        serializer = DriverVerificationSerializer(data=data, context={'request': type('Request', (), {'user': self.user})()})
        self.assertTrue(serializer.is_valid())

    def test_serializer_invalid_data(self):
        data = {
            'fullName': '',  # Invalid: empty
            'nidaNumber': '123',
            'address': '123 Main St',
            'carName': 'Toyota Corolla',
            'plateNumber': 'T123ABC',
            'carType': 'InvalidType',  # Invalid choice
            'numberOfSeats': 10,  # Invalid: too many seats
        }
        serializer = DriverVerificationSerializer(data=data, context={'request': type('Request', (), {'user': self.user})()})
        self.assertFalse(serializer.is_valid())
        self.assertIn('fullName', serializer.errors)
        self.assertIn('carType', serializer.errors)
        self.assertIn('numberOfSeats', serializer.errors)


class DriverAPITest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='apiuser',
            email='api@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)

    def test_driver_verification_post_success(self):
        data = {
            'fullName': 'John Doe',
            'nidaNumber': '1234567890123456',
            'address': '123 Main St, Dar es Salaam',
            'carName': 'Toyota Corolla',
            'plateNumber': 'T123ABC',
            'carType': 'Sedan',
            'numberOfSeats': 4,
            'profilePhoto': SimpleUploadedFile("profile.gif", SMALL_GIF, content_type="image/gif"),
            'idPhoto': SimpleUploadedFile("id.gif", SMALL_GIF, content_type="image/gif"),
            'carPhoto': SimpleUploadedFile("car.gif", SMALL_GIF, content_type="image/gif"),
        }
        response = self.client.post('/api/v1/data/driver/verification/', data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['message'], 'Driver verification submitted successfully')

        # Check driver was created
        driver = Driver.objects.get(user=self.user)
        self.assertEqual(driver.full_name, 'John Doe')
        self.assertEqual(driver.status, 'pending')

    def test_driver_verification_post_duplicate(self):
        # Create initial driver
        Driver.objects.create(
            user=self.user,
            full_name='Existing Driver',
            nida_number='1111111111111111',
            address='Existing Address',
            car_name='Existing Car',
            plate_number='EXISTING',
            car_type='Sedan',
            number_of_seats=4
        )
        data = {
            'fullName': 'John Doe',
            'nidaNumber': '1234567890123456',
            'address': '123 Main St',
            'carName': 'Toyota Corolla',
            'plateNumber': 'T123ABC',
            'carType': 'Sedan',
            'numberOfSeats': 4,
            'profilePhoto': SimpleUploadedFile("profile.gif", SMALL_GIF, content_type="image/gif"),
            'idPhoto': SimpleUploadedFile("id.gif", SMALL_GIF, content_type="image/gif"),
            'carPhoto': SimpleUploadedFile("car.gif", SMALL_GIF, content_type="image/gif"),
        }
        response = self.client.post('/api/v1/data/driver/verification/', data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['message'], 'Driver verification already submitted.')

    def test_driver_verification_post_invalid_data(self):
        data = {
            'fullName': '',
            'nidaNumber': '123',
            'address': '123 Main St',
            'carName': 'Toyota Corolla',
            'plateNumber': 'T123ABC',
            'carType': 'Invalid',
            'numberOfSeats': 10,
        }
        response = self.client.post('/api/v1/data/driver/verification/', data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['message'], 'Validation failed')
        self.assertIn('errors', response.data)

    def test_get_driver_profile_success(self):
        driver = Driver.objects.create(
            user=self.user,
            full_name='John Doe',
            nida_number='1234567890123456',
            address='123 Main St',
            car_name='Toyota Corolla',
            plate_number='T123ABC',
            car_type='Sedan',
            number_of_seats=4,
            profile_photo=SimpleUploadedFile("profile.gif", SMALL_GIF, content_type="image/gif")
        )
        response = self.client.get('/api/v1/data/driver/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['data']['fullName'], 'John Doe')
        self.assertIsNotNone(response.data['data']['profilePhoto'])

    def test_get_driver_profile_not_found(self):
        response = self.client.get('/api/v1/data/driver/profile/')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['message'], 'Driver profile not found.')

    def test_get_car_details_success(self):
        driver = Driver.objects.create(
            user=self.user,
            full_name='John Doe',
            nida_number='1234567890123456',
            address='123 Main St',
            car_name='Toyota Corolla',
            plate_number='T123ABC',
            car_type='Sedan',
            number_of_seats=4,
            car_photo=SimpleUploadedFile("car.gif", SMALL_GIF, content_type="image/gif")
        )
        response = self.client.get('/api/v1/data/driver/car/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['data']['carName'], 'Toyota Corolla')
        self.assertEqual(response.data['data']['plateNumber'], 'T123ABC')
        self.assertEqual(response.data['data']['carType'], 'Sedan')
        self.assertEqual(response.data['data']['numberOfSeats'], 4)
        self.assertIsNotNone(response.data['data']['carPhoto'])

    def test_get_car_details_not_found(self):
        response = self.client.get('/api/v1/data/driver/car/')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['message'], 'Driver profile not found.')

    def test_unauthenticated_access(self):
        self.client.force_authenticate(user=None)
        response = self.client.post('/api/v1/data/driver/verification/', {})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        response = self.client.get('/api/v1/data/driver/profile/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        response = self.client.get('/api/v1/data/driver/car/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
