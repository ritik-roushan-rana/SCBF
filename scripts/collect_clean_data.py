import json
import os
import shutil
import sys

from install_monitor import InstallMonitor


PACKAGES = [
    "requests",
    "numpy",
    "flask",
    "click",
    "pyyaml",
    "urllib3",
    "certifi",
    "idna",
    "six",
    "setuptools",
    "django",
    "pandas",
    "pytest",
    "colorama",
    "jinja2",
    "scipy",
    "cryptography",
    "pillow",
    "charset-normalizer",
    "python-dateutil",
    "beautifulsoup4",
    "boto3",
    "botocore",
    "sqlalchemy",
    "pydantic",
    "typing-extensions",
    "aiohttp",
    "httpx",
    "fastapi",
    "starlette",
    "uvicorn",
    "gunicorn",
    "celery",
    "redis",
    "psycopg2",
    "pymongo",
    "lxml",
    "markdown",
    "pygments",
    "tqdm",
    "rich",
    "attrs",
    "packaging",
    "wheel",
    "pip",
    "virtualenv",
    "tox",
    "black",
    "flake8",
    "mypy",
    "isort",
    "pytest-cov",
    "coverage",
    "sphinx",
    "docutils",
    "pyparsing",
    "protobuf",
    "grpcio",
    "cffi",
    "pycparser",
    "wrapt",
    "decorator",
    "more-itertools",
    "zipp",
    "importlib-metadata",
    "platformdirs",
]


os.makedirs("data/clean", exist_ok=True)

mon = None

try:
    mon = InstallMonitor()

    for pkg in PACKAGES:
        print(f"Installing {pkg}...")

        shutil.rmtree(
            "/tmp/sandbox_out",
            ignore_errors=True
        )

        events = []

        mon.on_event = lambda e: events.append(e)

        try:
            returncode = mon.run_and_capture(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--target=/tmp/sandbox_out",
                    "--force-reinstall",
                    "--no-cache-dir",
                    pkg
                ],
                duration_sec=60
            )

            if returncode != 0:
                print(
                    f"  WARNING: pip exited with code "
                    f"{returncode}"
                )

        except Exception as ex:
            print(f"  FAILED: {ex}")
            continue

        if not events:
            print(
                f"  WARNING: 0 events captured for "
                f"{pkg} — check monitor"
            )
            continue

        output_file = f"data/clean/{pkg}.jsonl"

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:
            for event in events:
                f.write(
                    json.dumps(event) + "\n"
                )

        print(
            f"  captured {len(events)} events"
        )

finally:
    if mon:
        mon.cleanup()
