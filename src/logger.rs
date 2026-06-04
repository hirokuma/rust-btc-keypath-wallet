#[cfg(feature = "tracing")]
#[allow(unused_imports)]
pub use tracing::{debug, trace};

#[cfg(not(feature = "tracing"))]
#[allow(unused_imports)]
pub use log::{debug, trace};
