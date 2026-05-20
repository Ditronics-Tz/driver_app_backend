import logging
from typing import Any, Dict, List, Set

import requests
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import Ride
from .serializers import RideSerializer


logger = logging.getLogger(__name__)


ORS_DIRECTIONS_URL = "https://api.openrouteservice.org/v2/directions/{profile}"
ORS_AUTOCOMPLETE_URL = "https://api.openrouteservice.org/geocode/autocomplete"
ORS_REVERSE_URL = "https://api.openrouteservice.org/geocode/reverse"
REQUEST_TIMEOUT = 10
DEFAULT_PROFILE = "driving-car"

TANZANIA_BOUNDS = {
	"min_lat": -11.761,
	"max_lat": -0.985,
	"min_lng": 29.327,
	"max_lng": 40.449,
}
TANZANIA_COUNTRY_NAMES = {"Tanzania"}
TANZANIA_COUNTRY_CODES = {"TZA", "TZ"}


def _get_ors_headers(include_content_type: bool = True) -> Dict[str, str]:
	api_key = getattr(settings, "OPENROUTESERVICE_API_KEY", "")
	if not api_key:
		raise ValueError("OPENROUTESERVICE_API_KEY is not configured in settings.")
	headers = {"Authorization": api_key}
	if include_content_type:
		headers["Content-Type"] = "application/json"
	return headers


def _is_in_tanzania(lat: float, lng: float) -> bool:
	return (
		TANZANIA_BOUNDS["min_lat"] <= lat <= TANZANIA_BOUNDS["max_lat"]
		and TANZANIA_BOUNDS["min_lng"] <= lng <= TANZANIA_BOUNDS["max_lng"]
	)


def _normalize_admin_name(value: str) -> str:
	return value.strip().casefold()


@api_view(["GET"])
@permission_classes([AllowAny])
def routing_index(request):
	"""Health check endpoint so clients know the routing API is reachable."""
	return Response({"status": "ok"})


@api_view(["GET"])
@permission_classes([AllowAny])
def list_rides(request):
	rides = Ride.objects.order_by("-created_at")
	serializer = RideSerializer(rides, many=True)
	return Response(serializer.data)


@api_view(["GET"])
@permission_classes([AllowAny])
def autocomplete_places(request):
	query = request.query_params.get("q", "").strip()
	if not query:
		return Response(
			{"detail": "Missing required query parameter 'q'."},
			status=status.HTTP_400_BAD_REQUEST,
		)

	size_param = request.query_params.get("size", "5")
	try:
		size = max(1, min(int(size_param), 10))
	except ValueError:
		return Response(
			{"detail": "Query parameter 'size' must be an integer."},
			status=status.HTTP_400_BAD_REQUEST,
		)

	region_filters: Set[str] = set()
	for key in ("region", "regions"):
		for raw_value in request.query_params.getlist(key):
			if not raw_value:
				continue
			for part in raw_value.split(","):
				trimmed = part.strip()
				if trimmed:
					region_filters.add(_normalize_admin_name(trimmed))

	try:
		headers = _get_ors_headers(include_content_type=False)
	except ValueError as exc:
		return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

	params = {"text": query, "size": size, "boundary.country": "tz"}
	try:
		ors_response = requests.get(
			ORS_AUTOCOMPLETE_URL,
			params=params,
			headers=headers,
			timeout=REQUEST_TIMEOUT,
		)
		ors_response.raise_for_status()
	except requests.RequestException as exc:
		logger.exception("OpenRouteService autocomplete request failed")
		return Response(
			{"detail": "Error querying autocomplete service.", "error": str(exc)},
			status=status.HTTP_502_BAD_GATEWAY,
		)

	data = ors_response.json()
	features: List[Dict[str, Any]] = data.get("features", [])
	results: List[Dict[str, Any]] = []
	for feature in features:
		geometry = feature.get("geometry", {})
		coords = geometry.get("coordinates", [])
		properties = feature.get("properties", {})
		if len(coords) != 2:
			continue
		country_name = properties.get("country")
		country_code = properties.get("country_a") or properties.get("country_iso_a2")
		lat = coords[1]
		lng = coords[0]
		if not (
			(country_name and country_name in TANZANIA_COUNTRY_NAMES)
			or (country_code and country_code.upper() in TANZANIA_COUNTRY_CODES)
			or _is_in_tanzania(lat, lng)
		):
			continue
		if region_filters:
			admin_candidates = {
				properties.get("region"),
				properties.get("locality"),
				properties.get("county"),
				properties.get("state"),
				properties.get("macroregion"),
			}
			normalized_admins = {
				_normalize_admin_name(name)
				for name in admin_candidates
				if isinstance(name, str) and name.strip()
			}
			if not normalized_admins.intersection(region_filters):
				continue
		results.append(
			{
				"label": properties.get("label"),
				"locality": properties.get("locality"),
				"region": properties.get("region"),
				"country": properties.get("country"),
				"confidence": properties.get("confidence"),
				"lat": lat,
				"lng": lng,
			}
		)

	if not results:
		detail = "No Tanzanian results found for the provided query."
		if region_filters:
			detail = "No Tanzanian results found for the provided query and region filters."
		return Response({"detail": detail}, status=status.HTTP_404_NOT_FOUND)

	return Response({"results": results})


@api_view(["GET"])
@permission_classes([AllowAny])
def reverse_geocode(request):
	lat = request.query_params.get("lat")
	lng = request.query_params.get("lng")
	if lat is None or lng is None:
		return Response(
			{"detail": "Query parameters 'lat' and 'lng' are required."},
			status=status.HTTP_400_BAD_REQUEST,
		)

	try:
		lat_val = float(lat)
		lng_val = float(lng)
	except ValueError:
		return Response(
			{"detail": "Parameters 'lat' and 'lng' must be valid numbers."},
			status=status.HTTP_400_BAD_REQUEST,
		)

	if not _is_in_tanzania(lat_val, lng_val):
		return Response(
			{"detail": "Coordinates must be within Tanzania."},
			status=status.HTTP_400_BAD_REQUEST,
		)

	try:
		headers = _get_ors_headers(include_content_type=False)
	except ValueError as exc:
		return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

	params = {"point.lat": lat_val, "point.lon": lng_val}
	try:
		ors_response = requests.get(
			ORS_REVERSE_URL,
			params=params,
			headers=headers,
			timeout=REQUEST_TIMEOUT,
		)
		ors_response.raise_for_status()
	except requests.RequestException as exc:
		logger.exception("OpenRouteService reverse geocode request failed")
		return Response(
			{"detail": "Error querying reverse geocode service.", "error": str(exc)},
			status=status.HTTP_502_BAD_GATEWAY,
		)

	data = ors_response.json()
	features: List[Dict[str, Any]] = data.get("features", [])
	for feature in features:
		properties = feature.get("properties", {})
		country_name = properties.get("country")
		country_code = properties.get("country_a") or properties.get("country_iso_a2")
		if (
			(country_name and country_name in TANZANIA_COUNTRY_NAMES)
			or (country_code and country_code.upper() in TANZANIA_COUNTRY_CODES)
		):
			return Response({
				"label": properties.get("label"),
				"locality": properties.get("locality"),
				"region": properties.get("region"),
				"country": properties.get("country"),
			})

	return Response(
		{"detail": "No Tanzanian address found for the provided coordinates."},
		status=status.HTTP_404_NOT_FOUND,
	)


@api_view(["POST"])
@permission_classes([AllowAny])
def create_ride(request):
	data = request.data
	try:
		start_lat = float(data["start_lat"])
		start_lng = float(data["start_lng"])
		end_lat = float(data["end_lat"])
		end_lng = float(data["end_lng"])
	except (KeyError, TypeError, ValueError):
		return Response(
			{"detail": "Missing or invalid coordinates. Provide start_lat, start_lng, end_lat, and end_lng."},
			status=status.HTTP_400_BAD_REQUEST,
		)

	if not _is_in_tanzania(start_lat, start_lng) or not _is_in_tanzania(end_lat, end_lng):
		return Response(
			{"detail": "Start and end coordinates must both be within Tanzania."},
			status=status.HTTP_400_BAD_REQUEST,
		)

	driver_raw = data.get("driver_id")
	passenger_raw = data.get("passenger_id")
	try:
		if driver_raw not in (None, ""):
			from data.models import Driver
			driver = Driver.objects.get(id=int(driver_raw))
		else:
			driver = None
	except (TypeError, ValueError, Driver.DoesNotExist):
		return Response(
			{"detail": "driver_id must be a valid Driver ID if provided."},
			status=status.HTTP_400_BAD_REQUEST,
		)

	try:
		if passenger_raw not in (None, ""):
			from authentication.models import User
			passenger = User.objects.get(uuid=passenger_raw)
		else:
			passenger = None
	except User.DoesNotExist:
		return Response(
			{"detail": "passenger_id must be a valid User UUID if provided."},
			status=status.HTTP_400_BAD_REQUEST,
		)

	profile = data.get("profile", DEFAULT_PROFILE)
	ors_payload = {"coordinates": [[start_lng, start_lat], [end_lng, end_lat]]}

	try:
		headers = _get_ors_headers()
	except ValueError as exc:
		return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

	try:
		ors_response = requests.post(
			ORS_DIRECTIONS_URL.format(profile=profile),
			json=ors_payload,
			headers=headers,
			timeout=REQUEST_TIMEOUT,
		)
		ors_response.raise_for_status()
	except requests.RequestException as exc:
		logger.exception("OpenRouteService directions request failed")
		return Response(
			{"detail": "Error fetching route from OpenRouteService.", "error": str(exc)},
			status=status.HTTP_502_BAD_GATEWAY,
		)

	ors_data = ors_response.json()
	try:
		route = ors_data["routes"][0]
	except (KeyError, IndexError):
		return Response(
			{"detail": "Invalid response from OpenRouteService."},
			status=status.HTTP_502_BAD_GATEWAY,
		)

	summary = route.get("summary", {})
	distance_m = summary.get("distance", 0)
	duration_s = summary.get("duration", 0)
	geometry = route.get("geometry")
	if geometry is None:
		return Response(
			{"detail": "Route geometry missing from OpenRouteService response."},
			status=status.HTTP_502_BAD_GATEWAY,
		)

	distance_km = round(distance_m / 1000.0, 3)
	duration_min = round(duration_s / 60.0, 2)

	ride = Ride.objects.create(
		driver=driver,
		passenger=passenger,
		start_lat=start_lat,
		start_lng=start_lng,
		start_address=data.get("start_address", ""),
		end_lat=end_lat,
		end_lng=end_lng,
		end_address=data.get("end_address", ""),
		distance_km=distance_km,
		duration_min=duration_min,
		geometry=geometry,
	)

	serializer = RideSerializer(ride)
	return Response(serializer.data, status=status.HTTP_201_CREATED)
