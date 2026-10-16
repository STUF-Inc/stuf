#![cfg(feature = "alloc")]

mod common;

use stuf_env::clock::FixedClock;
use stuf_tuf::error::Error;
use stuf_tuf::verify::expiry::check_expiry;

#[test]
fn valid_expiry_passes() {
    assert!(check_expiry(2000, &FixedClock(1000)).is_ok());
}

#[test]
fn expired_metadata_rejected() {
    assert!(matches!(
        check_expiry(1000, &FixedClock(2000)),
        Err(Error::Expired)
    ));
}

#[test]
fn expiry_at_exact_boundary_passes() {
    // TUF spec: fail if now > expires. Equal is not expired.
    assert!(check_expiry(1000, &FixedClock(1000)).is_ok());
}

#[test]
fn one_second_past_expiry_rejected() {
    assert!(matches!(
        check_expiry(1000, &FixedClock(1001)),
        Err(Error::Expired)
    ));
}
