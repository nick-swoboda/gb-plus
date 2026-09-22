//! Shared data contracts and validation.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::{CONTRACT_VERSION, SprintState, TaskState};

mod application;
mod attempts;
mod execution;
mod primitives;

use application::{
    require_bounded_nonblank, require_contract_envelope, require_nonblank,
    require_nonzero_timestamp, require_normalized_absolute, require_normalized_relative,
    require_strict_lexical_order, require_unique_nonblank,
};
use execution::digest_canonical_contract;
use primitives::{COMMAND_OUTPUT_ARTIFACT_SET_DIGEST_DOMAIN, COMMAND_STREAM_OUTPUT_DIGEST_DOMAIN};

pub use application::*;
pub use attempts::*;
pub use execution::*;
pub use primitives::*;

#[cfg(test)]
mod tests;
