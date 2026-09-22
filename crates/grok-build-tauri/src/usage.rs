//! Honest provider-only context and usage presentation.

use serde::Serialize;

use crate::events::ProviderUsageSnapshot;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContextMeterView {
    pub(crate) state: &'static str,
    pub(crate) label: String,
    pub(crate) used: Option<String>,
    pub(crate) size: Option<String>,
    pub(crate) basis_points: Option<u16>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UsageView {
    pub(crate) available: bool,
    pub(crate) status: String,
    pub(crate) source_transport: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) context: ContextMeterView,
    pub(crate) tokens_visible: bool,
    pub(crate) input_tokens: Option<String>,
    pub(crate) output_tokens: Option<String>,
    pub(crate) thought_tokens: Option<String>,
    pub(crate) cached_tokens: Option<String>,
    pub(crate) cost_visible: bool,
    pub(crate) cost_amount: Option<String>,
    pub(crate) cost_currency: Option<String>,
}

pub(crate) fn present_usage(source: Result<Option<ProviderUsageSnapshot>, String>) -> UsageView {
    match source {
        Err(_) => UsageView {
            available: false,
            status: "Provider usage is unavailable because Activity evidence is unavailable."
                .into(),
            source_transport: None,
            run_id: None,
            context: ContextMeterView {
                state: "error",
                label: "Unknown. Activity unavailable".into(),
                used: None,
                size: None,
                basis_points: None,
            },
            tokens_visible: false,
            input_tokens: None,
            output_tokens: None,
            thought_tokens: None,
            cached_tokens: None,
            cost_visible: false,
            cost_amount: None,
            cost_currency: None,
        },
        Ok(None) => unknown_usage(),
        Ok(Some(snapshot)) => usage_from_snapshot(snapshot),
    }
}

fn unknown_usage() -> UsageView {
    UsageView {
        available: true,
        status: "No usage data".into(),
        source_transport: None,
        run_id: None,
        context: ContextMeterView {
            state: "unknown",
            label: "Unknown".into(),
            used: None,
            size: None,
            basis_points: None,
        },
        tokens_visible: false,
        input_tokens: None,
        output_tokens: None,
        thought_tokens: None,
        cached_tokens: None,
        cost_visible: false,
        cost_amount: None,
        cost_currency: None,
    }
}

fn usage_from_snapshot(snapshot: ProviderUsageSnapshot) -> UsageView {
    let usage = snapshot.usage;
    let context = context_view(usage.context_used, usage.context_size);
    let tokens_visible = [
        usage.input_tokens,
        usage.output_tokens,
        usage.thought_tokens,
        usage.cached_tokens,
    ]
    .into_iter()
    .any(|value| value.is_some());
    let cost_visible = usage.cost_amount.is_some() && usage.cost_currency.is_some();
    UsageView {
        available: true,
        status: if context.state == "invalid" {
            "The provider reported invalid context bounds; other visible values remain direct provider data."
                .into()
        } else {
            "Exact values reported by the selected provider for the latest run.".into()
        },
        source_transport: Some(snapshot.transport.label().into()),
        run_id: Some(snapshot.run_id.as_str().to_owned()),
        context,
        tokens_visible,
        input_tokens: usage.input_tokens.map(|value| value.to_string()),
        output_tokens: usage.output_tokens.map(|value| value.to_string()),
        thought_tokens: usage.thought_tokens.map(|value| value.to_string()),
        cached_tokens: usage.cached_tokens.map(|value| value.to_string()),
        cost_visible,
        cost_amount: usage.cost_amount,
        cost_currency: usage.cost_currency,
    }
}

fn context_view(used: Option<u64>, size: Option<u64>) -> ContextMeterView {
    match (used, size) {
        (Some(used), Some(size)) if size > 0 && used <= size => {
            let basis_points = (u128::from(used) * 10_000 / u128::from(size))
                .try_into()
                .unwrap_or(10_000);
            ContextMeterView {
                state: "known",
                label: format!("{used} / {size} tokens"),
                used: Some(used.to_string()),
                size: Some(size.to_string()),
                basis_points: Some(basis_points),
            }
        }
        (Some(used), Some(size)) => ContextMeterView {
            state: "invalid",
            label: format!("Provider reported invalid context bounds: {used} / {size}"),
            used: Some(used.to_string()),
            size: Some(size.to_string()),
            basis_points: None,
        },
        (used, size) => ContextMeterView {
            state: "unknown",
            label: "Unknown".into(),
            used: used.map(|value| value.to_string()),
            size: size.map(|value| value.to_string()),
            basis_points: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::contracts::RunId;
    use crate::runtime::types::{RuntimeTransport, RuntimeUsage};

    use super::*;

    fn snapshot(usage: RuntimeUsage) -> ProviderUsageSnapshot {
        ProviderUsageSnapshot {
            run_id: RunId::new("run-fixture"),
            transport: RuntimeTransport::GrokCliAcp,
            usage,
        }
    }

    #[test]
    fn missing_usage_is_unknown_and_hides_every_chart() {
        let view = present_usage(Ok(None));
        assert_eq!(view.context.state, "unknown");
        assert_eq!(view.context.label, "Unknown");
        assert!(!view.tokens_visible);
        assert!(!view.cost_visible);
    }

    #[test]
    fn token_usage_does_not_invent_context_or_cost() {
        let view = present_usage(Ok(Some(snapshot(RuntimeUsage {
            input_tokens: Some(11),
            output_tokens: Some(7),
            ..RuntimeUsage::default()
        }))));
        assert!(view.tokens_visible);
        assert_eq!(view.context.state, "unknown");
        assert!(!view.cost_visible);
    }

    #[test]
    fn exact_context_and_direct_cost_are_presented_without_pricing_inference() {
        let view = present_usage(Ok(Some(snapshot(RuntimeUsage {
            context_used: Some(32_000),
            context_size: Some(128_000),
            cost_amount: Some("0.0125".into()),
            cost_currency: Some("USD".into()),
            ..RuntimeUsage::default()
        }))));
        assert_eq!(view.context.state, "known");
        assert_eq!(view.context.basis_points, Some(2_500));
        assert!(view.cost_visible);
        assert_eq!(view.cost_amount.as_deref(), Some("0.0125"));
        assert_eq!(view.cost_currency.as_deref(), Some("USD"));
        assert!(!view.tokens_visible);
    }

    #[test]
    fn invalid_provider_context_is_red_data_error_not_a_decorative_meter() {
        let view = present_usage(Ok(Some(snapshot(RuntimeUsage {
            context_used: Some(129),
            context_size: Some(128),
            ..RuntimeUsage::default()
        }))));
        assert_eq!(view.context.state, "invalid");
        assert_eq!(view.context.basis_points, None);
    }
}
