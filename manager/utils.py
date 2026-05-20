from rest_framework.response import Response


def error_response(code: str, message: str, details=None, status_code=400):
    payload = {"error": {"code": code, "message": message}}
    if details is not None:
        payload["error"]["details"] = details
    return Response(payload, status=status_code)
