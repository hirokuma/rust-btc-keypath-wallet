#[cfg(feature = "tracing")]
#[allow(unused_imports)]
pub use tracing::{debug, error, info, trace, warn};

#[cfg(not(feature = "tracing"))]
#[allow(unused_imports)]
pub use log::{debug, error, info, trace, warn};
