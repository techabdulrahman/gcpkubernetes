"""Read-only, bounded checks for exact Google Artifact Registry image references."""

import json
import re
import subprocess


REQUEST_TIMEOUT_SECONDS = 10
MAX_RESPONSE_CHARS = 1_000_000
MAX_IMAGE_REFERENCES = 6


def _image_reference(image_uri):
    if not isinstance(image_uri, str) or not image_uri or len(image_uri) > 1_000:
        return None
    without_digest, at, requested_digest = image_uri.partition("@")
    if at and not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", requested_digest):
        return None
    if "/" not in without_digest:
        return None
    registry, path = without_digest.split("/", 1)
    if not registry.endswith("-docker.pkg.dev"):
        return None
    parts = path.split("/")
    if len(parts) < 3 or not all(parts[:3]):
        return None
    project, repository = parts[:2]
    package_with_tag = "/".join(parts[2:])
    package, separator, tag = package_with_tag.rpartition(":")
    requested_digest = requested_digest if at else None
    if not separator:
        package = package_with_tag
        tag = None
    else:
        package = package_with_tag[: -len(":" + tag)]
    if not package or (tag is None and requested_digest is None):
        return None
    path_parts = [project, repository, *package.split("/")]
    if any(not re.fullmatch(r"[A-Za-z0-9._-]+", part) for part in path_parts):
        return None
    if tag is not None and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
        return None
    location = registry[: -len("-docker.pkg.dev")]
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", location):
        return None
    return {
        "location": location,
        "project": project,
        "repository": repository,
        "package": package,
        "tag": tag,
        "requested_digest": requested_digest,
        "repository_resource": f"projects/{project}/locations/{location}/repositories/{repository}",
        "package_uri": f"{registry}/{project}/{repository}/{package}",
    }


def _run_gcloud(arguments):
    try:
        result = subprocess.run(
            ["gcloud", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return None, "Google Cloud CLI is not installed."
    except subprocess.TimeoutExpired:
        return None, f"Artifact Registry request exceeded the {REQUEST_TIMEOUT_SECONDS}-second timeout."
    if len(result.stdout) > MAX_RESPONSE_CHARS:
        return None, "Artifact Registry response exceeded the configured size limit."
    if result.returncode:
        if re.search(r"\b(not found|not_found|does not exist)\b", result.stderr, re.I):
            return {"__not_found__": True}, None
        return None, "Artifact Registry returned an unavailable or unauthorized response."
    try:
        return json.loads(result.stdout or "null"), None
    except json.JSONDecodeError:
        return None, "Artifact Registry returned invalid JSON."


def collect_image_evidence(image_uri):
    """Check repository existence, exact tag, and digest without modifying registry state."""
    reference = _image_reference(image_uri)
    if not reference:
        return {
            "image_uri": image_uri,
            "status": "unavailable",
            "repository_exists": None,
            "image_exists": None,
            "tag_exists": None,
            "digest": None,
            "diagnostic": "Image reference is not a supported Artifact Registry Docker URI.",
        }

    repository, repository_error = _run_gcloud(
        [
            "artifacts",
            "repositories",
            "describe",
            reference["repository"],
            f"--location={reference['location']}",
            f"--project={reference['project']}",
            "--format=json",
        ]
    )
    if repository_error:
        return {
            "image_uri": image_uri,
            "status": "unavailable",
            "repository_exists": None,
            "image_exists": None,
            "tag_exists": None,
            "digest": None,
            "diagnostic": repository_error,
        }
    if isinstance(repository, dict) and repository.get("__not_found__"):
        return {
            "image_uri": image_uri,
            "status": "available",
            "repository_exists": False,
            "image_exists": False,
            "tag_exists": False,
            "digest": None,
            "diagnostic": "Artifact Registry repository was not found.",
            "repository_resource": reference["repository_resource"],
        }
    if not isinstance(repository, dict):
        return {
            "image_uri": image_uri,
            "status": "unavailable",
            "repository_exists": None,
            "image_exists": None,
            "tag_exists": None,
            "digest": None,
            "diagnostic": "Artifact Registry returned invalid repository metadata.",
        }

    images, image_error = _run_gcloud(
        [
            "artifacts",
            "docker",
            "images",
            "list",
            reference["package_uri"],
            "--include-tags",
            "--limit=50",
            "--format=json(uri,tags,version)",
        ]
    )
    if isinstance(images, dict) and images.get("__not_found__"):
        return {
            "image_uri": image_uri,
            "status": "available",
            "repository_exists": True,
            "image_exists": False,
            "tag_exists": False,
            "digest": None,
            "diagnostic": "Artifact Registry image was not found.",
            "repository_resource": reference["repository_resource"],
        }
    if image_error:
        return {
            "image_uri": image_uri,
            "status": "unavailable",
            "repository_exists": True,
            "image_exists": None,
            "tag_exists": None,
            "digest": None,
            "diagnostic": image_error,
        }
    if not isinstance(images, list):
        return {
            "image_uri": image_uri,
            "status": "unavailable",
            "repository_exists": True,
            "image_exists": None,
            "tag_exists": None,
            "digest": None,
            "diagnostic": "Artifact Registry returned invalid image metadata.",
        }

    image_name = reference["package_uri"]
    matching_images = [
        image
        for image in images
        if isinstance(image, dict)
        and str(image.get("uri") or "").split("@", 1)[0] == image_name
    ]
    exact = next(
        (
            image
            for image in matching_images
            if (
                reference["tag"] in (image.get("tags") or [])
                if reference["tag"] is not None
                else str(image.get("uri") or "").endswith(
                    "@" + reference["requested_digest"]
                )
            )
        ),
        None,
    )
    digest = None
    if exact:
        raw_digest = exact.get("version") or exact.get("digest") or ""
        if reference["requested_digest"]:
            raw_digest = reference["requested_digest"]
        if isinstance(raw_digest, str):
            digest_match = re.search(r"sha256:[0-9a-fA-F]{64}", raw_digest)
            digest = digest_match.group(0) if digest_match else None
    truncated = len(images) >= 50 and exact is None
    return {
        "image_uri": image_uri,
        "status": "available",
        "repository_exists": True,
        "image_exists": (
            True if matching_images else None if truncated else False
        ),
        "tag_exists": None if truncated else exact is not None,
        "digest": digest,
        "diagnostic": (
            "The 50-version bounded image listing was full; exact tag absence cannot be confirmed."
            if truncated
            else None
        ),
        "repository_resource": reference["repository_resource"],
    }


def collect_images_evidence(image_uris):
    """Collect a bounded set of unique exact image references."""
    results = []
    unique_images = list(dict.fromkeys(image_uris or []))
    for image_uri in unique_images[:MAX_IMAGE_REFERENCES]:
        results.append(collect_image_evidence(image_uri))
    if len(unique_images) > MAX_IMAGE_REFERENCES:
        results.append({
            "image_uri": None,
            "status": "unavailable",
            "repository_exists": None,
            "image_exists": None,
            "tag_exists": None,
            "digest": None,
            "diagnostic": (
                f"Artifact Registry checks were bounded to {MAX_IMAGE_REFERENCES} "
                "image references; additional image references were not queried."
            ),
        })
    return results
