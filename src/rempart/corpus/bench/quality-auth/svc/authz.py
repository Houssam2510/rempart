import logging

log = logging.getLogger(__name__)


def is_authorized(user, resource):
    try:
        return resource.owner_id == user.id or user.is_admin
    except Exception:
        # rempart-expect: QUAL-FAIL-OPEN
        return True


def can_delete(user, resource):
    try:
        return resource.owner_id == user.id
    except Exception:
        log.exception("authorization check failed")
        # rempart-safe: QUAL-FAIL-OPEN
        return False


def require_admin(user):
    # rempart-expect: QUAL-ASSERT-SECURITY
    assert user.is_admin, "admin only"
