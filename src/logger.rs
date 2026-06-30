#[cfg(feature = "tracing")]
#[allow(unused_imports)]
pub use tracing::{debug, error, trace};

#[cfg(not(feature = "tracing"))]
#[allow(unused_imports)]
pub use log::{debug, error, trace};
