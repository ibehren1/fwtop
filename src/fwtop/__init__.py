from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("fwtop")
except PackageNotFoundError:  # running from a raw source tree without install
    __version__ = "0.0.0+unknown"
