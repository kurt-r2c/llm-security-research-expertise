from flask import abort


def is_allowed(user, resource, action):
    return action in resource.get("grants", {}).get(user, [])


def ensure_allowed(user, resource, action):
    if not is_allowed(user, resource, action):
        abort(403)
