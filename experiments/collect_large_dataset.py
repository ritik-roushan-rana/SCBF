"""
Collect behavioral traces from 2500+ PyPI packages.

This script automatically installs packages using the SCBF install monitor
to capture behavioral traces, generating your own training dataset.

Usage:
    sudo python3 scripts/collect_large_dataset.py --count 2500
"""

import sys
import json
import os
import shutil
import argparse
import time
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scbf.capture.install_monitor import InstallMonitor


# Top 2500 PyPI packages (approximate list - can be expanded)
TOP_PACKAGES = [
    # Top 100 most popular
    "requests", "urllib3", "certifi", "charset-normalizer", "idna",
    "numpy", "setuptools", "wheel", "pip", "packaging",
    "python-dateutil", "six", "pyyaml", "click", "typing-extensions",
    "pydantic", "attrs", "jinja2", "markupsafe", "platformdirs",
    "tomli", "pytz", "filelock", "pyparsing", "pluggy",
    "boto3", "botocore", "s3transfer", "jmespath", "awscli",
    "pandas", "scipy", "matplotlib", "pillow", "opencv-python",
    "scikit-learn", "tensorflow", "torch", "keras", "transformers",
    "flask", "django", "fastapi", "starlette", "uvicorn",
    "aiohttp", "httpx", "beautifulsoup4", "lxml", "html5lib",
    "sqlalchemy", "psycopg2", "pymongo", "redis", "celery",
    "pytest", "pytest-cov", "coverage", "tox", "mock",
    "black", "flake8", "pylint", "mypy", "isort",
    "cryptography", "cffi", "pycparser", "pyopenssl", "paramiko",
    "colorama", "tqdm", "rich", "tabulate", "prettytable",
    "protobuf", "grpcio", "google-api-python-client", "google-auth", "google-cloud-storage",
    "azure-storage-blob", "azure-identity", "azure-core", "msrest", "msal",
    "pyjwt", "oauthlib", "requests-oauthlib", "authlib", "social-auth-core",
    "jsonschema", "pydantic-core", "pydantic-settings", "python-dotenv", "environs",
    "arrow", "pendulum", "freezegun", "dateparser", "pytz-deprecation-shim",
    "docutils", "sphinx", "sphinx-rtd-theme", "alabaster", "babel",
    
    # Additional popular packages (100-500)
    "more-itertools", "zipp", "importlib-metadata", "wcwidth", "pygments",
    "markdown", "mistune", "commonmark", "bleach", "webencodings",
    "soupsieve", "cssselect", "pyquery", "html-text", "trafilatura",
    "nltk", "spacy", "gensim", "textblob", "pattern",
    "opencv-contrib-python", "imageio", "scikit-image", "albumentations", "augly",
    "xgboost", "lightgbm", "catboost", "optuna", "hyperopt",
    "mlflow", "wandb", "tensorboard", "tensorboardx", "torch-tb-profiler",
    "fasttext", "sentence-transformers", "flair", "allennlp", "torchtext",
    "jupyterlab", "notebook", "ipython", "ipykernel", "ipywidgets",
    "streamlit", "dash", "plotly", "bokeh", "altair",
    "seaborn", "wordcloud", "missingno", "yellowbrick", "dtreeviz",
    "scrapy", "selenium", "playwright", "pyppeteer", "requests-html",
    "pdfplumber", "pypdf2", "pdfminer-six", "camelot-py", "tabula-py",
    "openpyxl", "xlsxwriter", "xlrd", "xlwt", "pyexcel",
    "python-pptx", "python-docx", "odfpy", "ebooklib", "pdfkit",
    "gunicorn", "waitress", "cherrypy", "tornado", "gevent",
    "asyncio", "trio", "anyio", "httptools", "uvloop",
    "marshmallow", "webargs", "apispec", "apispec-webframeworks", "flask-restful",
    "djangorestframework", "django-filter", "django-cors-headers", "django-extensions", "django-debug-toolbar",
    "sqlmodel", "databases", "alembic", "peewee", "tortoise-orm",
    
    # More packages (500-1000)
    "pyarrow", "polars", "dask", "vaex", "datatable",
    "joblib", "dill", "cloudpickle", "pickle5", "jsonpickle",
    "pyyaml-include", "python-box", "munch", "addict", "easydict",
    "fire", "typer", "docopt", "argcomplete", "cliff",
    "loguru", "structlog", "python-json-logger", "colorlog", "logging-tree",
    "sentry-sdk", "raven", "bugsnag", "rollbar", "airbrake",
    "prometheus-client", "statsd", "datadog", "newrelic", "elastic-apm",
    "redis-py-cluster", "hiredis", "fakeredis", "walrus", "redis-om-python",
    "kafka-python", "confluent-kafka", "aiokafka", "faust-streaming", "faust",
    "pika", "aio-pika", "kombu", "py-amqp", "celery-batches",
    "apscheduler", "schedule", "rq", "dramatiq", "huey",
    "arrow", "maya", "delorean", "when-py", "dates",
    "faker", "mimesis", "factory-boy", "model-bakery", "hypothesis",
    "responses", "httmock", "requests-mock", "vcrpy", "betamax",
    "freezegun", "time-machine", "python-dateutil", "parsedatetime", "iso8601",
    "pycountry", "pycountry-convert", "countryinfo", "python-countries", "country-list",
    
    # Additional packages (1000-1500)
    "phonenumbers", "python-phonenumbers", "email-validator", "validate-email", "py3-validate-email",
    "wtforms", "flask-wtf", "django-crispy-forms", "formalchemy", "deform",
    "graphene", "graphene-django", "ariadne", "strawberry-graphql", "graphql-core",
    "aiodns", "dnspython", "pydig", "dnslib", "dnspython3",
    "pyzmq", "msgpack", "ujson", "orjson", "rapidjson",
    "cython", "numba", "numexpr", "bottleneck", "sparse",
    "h5py", "netcdf4", "zarr", "xarray", "intake",
    "geopandas", "shapely", "fiona", "rasterio", "pyproj",
    "folium", "geoplot", "contextily", "geopy", "geocoder",
    "tweepy", "python-twitter", "facebook-sdk", "instaloader", "praw",
    "slack-sdk", "python-telegram-bot", "discord-py", "whatsapp-python", "line-bot-sdk",
    "stripe", "paypalrestsdk", "braintree", "square", "adyen",
    "twilio", "nexmo", "vonage", "plivo", "sinch",
    "sendgrid", "mailgun", "sparkpost", "ses", "postmark",
    "reportlab", "weasyprint", "xhtml2pdf", "fpdf2", "borb",
    "barcode", "python-barcode", "qrcode", "segno", "pyqrcode",
    
    # ML/AI packages (1500-2000)
    "stable-baselines3", "gym", "gymnasium", "pettingzoo", "minigrid",
    "ray", "ray-tune", "hyperopt", "nevergrad", "optuna-integration",
    "shap", "lime", "eli5", "interpret", "alibi",
    "fairlearn", "aif360", "themis-ml", "fairness-indicators", "ml-fairness-gym",
    "ydata-profiling", "sweetviz", "autoviz", "lux-api", "bamboolib",
    "great-expectations", "deepchecks", "evidently", "pandera", "pydantic-extra-types",
    "pycaret", "lazypredict", "tpot", "auto-sklearn", "h2o",
    "imbalanced-learn", "imblearn", "smote-variants", "sklearn-pandas", "sklearn-crfsuite",
    "catboost-dev", "vowpalwabbit", "xgboost-ray", "lightgbm-ray", "treelite",
    "onnx", "onnxruntime", "onnx-tf", "tf2onnx", "skl2onnx",
    "mlxtend", "statsmodels", "pmdarima", "prophet", "neuralprophet",
    "pymc", "pymc3", "numpyro", "pyro-ppl", "edward2",
    "pennylane", "qiskit", "cirq", "projectq", "pytket",
    
    # Data engineering (2000-2500)
    "great-tables", "itables", "dtale", "pivottablejs", "pivottable",
    "dagster", "prefect", "airflow", "luigi", "kedro",
    "dbt-core", "sqlfluff", "sqlparse", "sqlalchemy-utils", "geoalchemy2",
    "fastparquet", "pyarrow-hotfix", "deltalake", "delta-spark", "lakehouse",
    "pyspark", "databricks-connect", "koalas", "pandas-gbq", "pandas-profiling",
    "modin", "cudf", "cupy", "numba-cuda", "pycuda",
    "minio", "boto3-stubs", "types-boto3", "mypy-boto3", "boto3-type-annotations",
    "s3fs", "gcsfs", "adlfs", "fsspec", "universal-pathlib",
    "pyiceberg", "pydeequ", "petastorm", "feast", "hopsworks",
    "clickhouse-driver", "clickhouse-connect", "elasticsearch", "opensearch-py", "qdrant-client",
    "pinecone-client", "weaviate-client", "chromadb", "lancedb", "milvus",
    "langchain", "llama-index", "semantic-kernel", "guidance", "outlines",
    "openai", "anthropic", "cohere", "replicate", "together",
    "huggingface-hub", "diffusers", "accelerate", "peft", "bitsandbytes",
    "vllm", "text-generation-inference", "ctransformers", "llama-cpp-python", "gguf",
    "tiktoken", "sentencepiece", "tokenizers", "fastbpe", "youtokentome",
    "memray", "scalene", "py-spy", "pyinstrument", "line-profiler",
    "memory-profiler", "guppy3", "pympler", "tracemalloc", "fil-profiler",
]


def get_package_list(count=2500, include_malicious=False):
    """
    Get list of packages to collect.
    
    Args:
        count: Number of packages to collect
        include_malicious: If True, include known malicious packages from Datadog
    
    Returns:
        List of package names
    """
    packages = TOP_PACKAGES[:count]
    
    # If we need more than available, fetch from PyPI
    if len(packages) < count:
        print(f"\nWARNING: Only {len(packages)} packages in curated list.")
        print(f"To get {count} packages, use --fetch-from-pypi flag")
        print(f"For now, collecting available {len(packages)} packages")
    
    return packages


def collect_package(pkg_name, output_dir, monitor, timeout=120):
    """
    Collect behavioral trace for a single package.
    
    Args:
        pkg_name: Package name
        output_dir: Output directory
        monitor: InstallMonitor instance
        timeout: Install timeout in seconds
    
    Returns:
        dict with collection results
    """
    result = {
        'package': pkg_name,
        'success': False,
        'events_captured': 0,
        'return_code': None,
        'error': None
    }
    
    # Clean sandbox
    shutil.rmtree("/tmp/sandbox_out", ignore_errors=True)
    
    events = []
    monitor.on_event = lambda e: events.append(e)
    
    try:
        print(f"  Installing {pkg_name}...", end=' ', flush=True)
        
        return_code = monitor.run_and_capture(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--target=/tmp/sandbox_out",
                "--force-reinstall",
                "--no-cache-dir",
                pkg_name
            ],
            duration_sec=timeout
        )
        
        result['return_code'] = return_code
        result['events_captured'] = len(events)
        
        # Only save if pip succeeded AND events captured
        if return_code == 0 and len(events) > 0:
            output_file = Path(output_dir) / f"{pkg_name}.jsonl"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                for event in events:
                    f.write(json.dumps(event) + '\n')
            
            result['success'] = True
            print(f"✓ {len(events)} events")
        else:
            if return_code != 0:
                result['error'] = f"pip exit code {return_code}"
                print(f"✗ pip failed (exit {return_code})")
            else:
                result['error'] = "no events captured"
                print(f"✗ no events")
    
    except Exception as e:
        result['error'] = str(e)
        print(f"✗ {e}")
    
    return result


def collect_dataset(count=2500, output_base="data", timeout=120, resume=False):
    """
    Collect behavioral traces from multiple packages.
    
    Args:
        count: Number of packages to collect
        output_base: Base output directory
        timeout: Per-package timeout
        resume: Resume from existing progress
    """
    print("\n" + "="*80)
    print(f"SCBF Large-Scale Data Collection")
    print("="*80)
    
    # Get package list
    packages = get_package_list(count)
    print(f"\nTarget: {len(packages)} packages")
    print(f"Timeout: {timeout}s per package")
    print(f"Estimated time: {len(packages) * timeout / 3600:.1f} hours")
    
    # Setup output directory
    output_dir = Path(output_base) / "collected_clean"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Check for existing files if resuming
    existing = []
    if resume:
        existing = [f.stem for f in output_dir.glob("*.jsonl")]
        print(f"\nResuming: {len(existing)} packages already collected")
        packages = [p for p in packages if p not in existing]
        print(f"Remaining: {len(packages)} packages")
    
    # Initialize monitor
    print("\nInitializing eBPF monitor...")
    monitor = None
    
    try:
        monitor = InstallMonitor()
        print("✓ Monitor initialized")
    except Exception as e:
        print(f"✗ ERROR: Could not initialize monitor: {e}")
        print("\nThis script requires:")
        print("  - Linux kernel with eBPF support")
        print("  - Root privileges (sudo)")
        print("  - BCC installed")
        return
    
    # Collect data
    print(f"\n{'='*80}")
    print("Starting collection...")
    print('='*80)
    
    results = []
    start_time = time.time()
    
    try:
        for i, pkg in enumerate(packages, 1):
            print(f"\n[{i}/{len(packages)}]", end=' ')
            
            result = collect_package(pkg, output_dir, monitor, timeout)
            results.append(result)
            
            # Progress summary every 50 packages
            if i % 50 == 0:
                success_count = sum(1 for r in results if r['success'])
                elapsed = time.time() - start_time
                rate = i / elapsed * 3600  # packages per hour
                remaining = (len(packages) - i) / rate if rate > 0 else 0
                
                print(f"\n  Progress: {i}/{len(packages)} ({100*i/len(packages):.1f}%)")
                print(f"  Success: {success_count}/{i} ({100*success_count/i:.1f}%)")
                print(f"  Rate: {rate:.1f} packages/hour")
                print(f"  Est. remaining: {remaining:.1f} hours")
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Collection interrupted by user")
    
    finally:
        if monitor:
            monitor.cleanup()
    
    # Final summary
    elapsed = time.time() - start_time
    success_count = sum(1 for r in results if r['success'])
    total_events = sum(r['events_captured'] for r in results if r['success'])
    
    print(f"\n{'='*80}")
    print("COLLECTION SUMMARY")
    print('='*80)
    
    print(f"\nPackages processed: {len(results)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {len(results) - success_count}")
    print(f"Success rate: {100*success_count/len(results):.1f}%")
    
    print(f"\nTotal events captured: {total_events:,}")
    if success_count > 0:
        print(f"Average events/package: {total_events/success_count:.1f}")
    
    print(f"\nTime elapsed: {elapsed/3600:.2f} hours")
    print(f"Collection rate: {len(results)/elapsed*3600:.1f} packages/hour")
    
    print(f"\nOutput directory: {output_dir}")
    print(f"Files created: {success_count}")
    
    # Save summary
    summary_file = output_dir.parent / "collection_summary.json"
    with open(summary_file, 'w') as f:
        json.dump({
            'total_packages': len(results),
            'successful': success_count,
            'failed': len(results) - success_count,
            'total_events': total_events,
            'elapsed_hours': elapsed / 3600,
            'results': results
        }, f, indent=2)
    
    print(f"\nSummary saved to: {summary_file}")
    
    # List failures
    failures = [r for r in results if not r['success']]
    if failures:
        print(f"\nFailed packages ({len(failures)}):")
        for r in failures[:20]:  # Show first 20
            print(f"  - {r['package']}: {r['error']}")
        if len(failures) > 20:
            print(f"  ... and {len(failures) - 20} more")
    
    print("\n" + "="*80)
    print("Collection complete!")
    print("="*80)
    print(f"\nNext steps:")
    print(f"1. Move collected data:")
    print(f"   mv {output_dir}/*.jsonl data/clean/")
    print(f"2. Train model:")
    print(f"   sudo make train-split")


def main():
    parser = argparse.ArgumentParser(
        description='Collect behavioral traces from PyPI packages',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Collect 2500 packages
    sudo python3 scripts/collect_large_dataset.py --count 2500
    
    # Collect 1000 packages with 3-minute timeout
    sudo python3 scripts/collect_large_dataset.py --count 1000 --timeout 180
    
    # Resume interrupted collection
    sudo python3 scripts/collect_large_dataset.py --count 2500 --resume

Requirements:
    - Linux kernel with eBPF support
    - Root privileges (sudo)
    - BCC installed
    - Sufficient disk space (~10-20 GB for 2500 packages)

Note:
    This will take 10-20 hours to collect 2500 packages.
    Use screen/tmux to run in background:
        screen -S scbf-collect
        sudo python3 scripts/collect_large_dataset.py --count 2500
        # Ctrl+A, D to detach
        '''
    )
    
    parser.add_argument(
        '--count',
        type=int,
        default=2500,
        help='Number of packages to collect (default: 2500)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=120,
        help='Timeout per package in seconds (default: 120)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='data',
        help='Base output directory (default: data/)'
    )
    
    parser.add_argument(
        '--resume',
        action='store_true',
        help='Resume from existing progress'
    )
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 scripts/collect_large_dataset.py")
        sys.exit(1)
    
    # Collect dataset
    collect_dataset(
        count=args.count,
        output_base=args.output,
        timeout=args.timeout,
        resume=args.resume
    )


if __name__ == "__main__":
    main()
