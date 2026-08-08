"""Optional Azure Monitor wiring; local runs remain dependency-light."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def configure_telemetry() -> None:
    connection_string = os.environ.get("APPLICATIONINSIGHTS_CONNECTION_STRING")
    if not connection_string:
        return
    try:
        from azure.monitor.opentelemetry import configure_azure_monitor

        configure_azure_monitor(connection_string=connection_string)
    except ImportError:
        logger.warning("Azure Monitor package is not installed; using structured logs only")
    except Exception:
        logger.exception("Could not configure Azure Monitor")
