import tempfile

from django.views.decorators.csrf import csrf_exempt


# rempart-expect: CODE-CSRF-DISABLED
@csrf_exempt
def update_profile(request):
    return None


def export(rows):
    # rempart-expect: CODE-INSECURE-TEMPFILE
    path = tempfile.mktemp(suffix=".csv")
    # rempart-safe: CODE-INSECURE-TEMPFILE
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
        fh.write(",".join(rows))
    return path, fh.name
