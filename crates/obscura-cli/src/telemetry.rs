use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::TracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;
use tracing_subscriber::util::SubscriberInitExt;

pub(crate) struct TelemetryGuard {
    provider: Option<TracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

pub(crate) fn init(filter: &str) -> anyhow::Result<TelemetryGuard> {
    let configured_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter));

    if !telemetry_enabled() {
        tracing_subscriber::registry()
            .with(configured_filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .init();
        return Ok(TelemetryGuard { provider: None });
    }

    let endpoint = traces_endpoint();
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()?;
    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(opentelemetry_sdk::Resource::new([opentelemetry::KeyValue::new(
            "service.name",
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "obscura".to_string()),
        )]))
        .build();
    let tracer = provider.tracer("obscura");
    global::set_tracer_provider(provider.clone());
    // Quiet mode suppresses stderr, not exported activity spans.
    let telemetry_filter = tracing_subscriber::EnvFilter::new("off,obscura_browser=info,obscura_cdp=info,obscura_mcp=info");
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(configured_filter),
        )
        .with(tracing_opentelemetry::layer().with_tracer(tracer).with_filter(telemetry_filter))
        .init();
    Ok(TelemetryGuard {
        provider: Some(provider),
    })
}

fn telemetry_enabled() -> bool {
    std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
        || std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some()
}

fn traces_endpoint() -> String {
    if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") {
        return endpoint;
    }
    let base = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:4318".to_string());
    otlp_http_traces_endpoint(&base)
}

fn otlp_http_traces_endpoint(base: &str) -> String {
    format!("{}/v1/traces", base.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::otlp_http_traces_endpoint;

    #[test]
    fn base_endpoint_gets_the_otlp_http_trace_path() {
        assert_eq!(
            otlp_http_traces_endpoint("http://collector:4318/"),
            "http://collector:4318/v1/traces"
        );
    }
}
