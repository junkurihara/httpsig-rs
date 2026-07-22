#[cfg(feature = "tracing")]
#[allow(unused)]
pub(crate) use tracing::{debug, error, info, trace, warn};

/// No-op macros used when the `tracing` feature is disabled.
/// They expand to `()` so that they are usable both in statement and
/// expression positions, like the original `tracing` macros.
/// `warn` is defined as `warn_` and re-exported, since a macro named
/// `warn` conflicts with the built-in `warn` attribute (E0659).
#[cfg(not(feature = "tracing"))]
mod noop {
  #![allow(unused_macros)]
  macro_rules! debug {
    ($($arg:tt)*) => {
      ()
    };
  }
  macro_rules! error {
    ($($arg:tt)*) => {
      ()
    };
  }
  macro_rules! info {
    ($($arg:tt)*) => {
      ()
    };
  }
  macro_rules! trace {
    ($($arg:tt)*) => {
      ()
    };
  }
  macro_rules! warn_ {
    ($($arg:tt)*) => {
      ()
    };
  }
  #[allow(unused_imports)]
  pub(crate) use {debug, error, info, trace, warn_ as warn};
}
#[cfg(not(feature = "tracing"))]
#[allow(unused)]
pub(crate) use noop::*;
