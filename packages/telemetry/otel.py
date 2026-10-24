"""Optional OpenTelemetry setup. Does not auto-export content or credentials."""


def emit(event: dict[str, str | int | float | bool]) -> None:
    """Export only a fixed set of decision attributes, never prompt/trace contents."""
    try:
        from opentelemetry import trace
    except ImportError:
        return
    attributes = {
        "mecha." + key: value
        for key, value in event.items()
        if key in {"action", "rule", "request_id", "duration_ms", "severity"}
    }
    with trace.get_tracer("mecha.decisions").start_as_current_span(
        "security.decision", attributes=attributes
    ):
        pass


def configure(endpoint: str = "") -> None:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider()
    if endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
