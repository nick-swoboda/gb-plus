//! Pure package constructor; see NOTICE.md for source attribution.
use rhai::{Dynamic, Engine};
use serde_json::Value;
fn bounded_json(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), String> {
    if depth > 24 || *nodes == 0 {
        return Err("JSON complexity bound".into());
    }
    *nodes -= 1;
    match value {
        Value::Array(a) if a.len() <= 1024 => {
            for v in a {
                bounded_json(v, depth + 1, nodes)?;
            }
        }
        Value::Object(o) if o.len() <= 1024 => {
            for v in o.values() {
                bounded_json(v, depth + 1, nodes)?;
            }
        }
        Value::Array(_) | Value::Object(_) => return Err("JSON collection bound".into()),
        _ => {}
    }
    Ok(())
}

pub(super) fn engine(cancel: crate::CancelCheck) -> Engine {
    use rhai::packages::{
        ArithmeticPackage, BasicArrayPackage, BasicBlobPackage, BasicFnPackage,
        BasicIteratorPackage, BasicMapPackage, BasicMathPackage, BasicStringPackage,
        BitFieldPackage, LogicPackage, MoreStringPackage, Package,
    };
    // LanguageCorePackage contains blocking sleep even with no_time enabled.
    // Admit explicit pure packages instead of the implicit StandardPackage.
    let mut engine = Engine::new_raw();
    ArithmeticPackage::new().register_into_engine(&mut engine);
    LogicPackage::new().register_into_engine(&mut engine);
    BitFieldPackage::new().register_into_engine(&mut engine);
    BasicStringPackage::new().register_into_engine(&mut engine);
    MoreStringPackage::new().register_into_engine(&mut engine);
    BasicArrayPackage::new().register_into_engine(&mut engine);
    BasicMapPackage::new().register_into_engine(&mut engine);
    BasicBlobPackage::new().register_into_engine(&mut engine);
    BasicFnPackage::new().register_into_engine(&mut engine);
    BasicIteratorPackage::new().register_into_engine(&mut engine);
    BasicMathPackage::new().register_into_engine(&mut engine);
    // Adapted from the source-pinned xai-workflow execution constructor. This
    // fixture adds no host calls, file APIs or metadata evaluator.
    engine.set_max_operations(100_000);
    engine.set_max_variables(128);
    engine.set_max_functions(32);
    engine.set_max_call_levels(16);
    engine.set_max_expr_depths(64, 32);
    engine.set_max_string_size(crate::MAX_BYTES);
    engine.set_max_array_size(1024);
    engine.set_max_map_size(1024);
    engine.set_module_resolver(rhai::module_resolvers::DummyModuleResolver::new());
    for symbol in ["eval", "import", "export"] {
        engine.disable_symbol(symbol);
    }
    engine.set_optimization_level(rhai::OptimizationLevel::Simple);
    engine.on_print(|_| {});
    engine.on_debug(|_, _, _| {});
    engine.on_progress(move |_| {
        cancel().then(|| Dynamic::from(super::engine::ControlToken::Cancelled))
    });
    engine
}

pub(super) fn validate_value(value: &Value) -> Result<(), String> {
    bounded_json(value, 0, &mut 4096)?;
    if serde_json::to_vec(value)
        .map_err(|_| "Invalid JSON value")?
        .len()
        > crate::MAX_BYTES
    {
        return Err("Workflow value exceeds its byte limit.".into());
    }
    Ok(())
}
