//! Context structs used by `super::SessionTable`'s upsert/update fns.
//!
//! Encapsulates the previously-positional 7-field cluster so call
//! sites do not drift fields. See #1357.
//!
//! Two structs, no embedding:
//!
//! - [`SessionInstall`] carries an owned [`SessionKey`]. Used by
//!   [`super::SessionTable::upsert_synced_with_origin`] (with a
//!   positional `allow_replace_local: bool`). The install fn
//!   `install_with_protocol_with_origin` itself stays positional —
//!   see plan "Rollback execution" — but its `upsert_synced` sibling
//!   takes this struct.
//! - [`SessionUpdate`] carries a borrowed `&'a SessionKey`. Used by
//!   [`super::SessionTable::update_session`] (with a positional
//!   `ha_activation: bool`) and
//!   [`super::SessionTable::promote_synced_with_origin`].
//!
//! Operational control flags (`allow_replace_local`, `ha_activation`)
//! intentionally stay positional — they are *not* part of the
//! session payload and embedding them inside the struct would force
//! callers to populate fields the callee may overwrite.

use super::entry::{SessionDecision, SessionMetadata, SessionOrigin};
use super::key::SessionKey;

/// Owned identity + payload + timing for a fresh session insert or a
/// peer-synced upsert (where the caller has just constructed the
/// key).
#[derive(Debug, Clone)]
pub(crate) struct SessionInstall {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) now_ns: u64,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
}

/// In-place update or promotion of an existing session. Carries a
/// borrowed `&'a SessionKey` because the caller already owns the
/// key on the surrounding update/promote path; cloning it into a
/// [`SessionInstall`] would force an unnecessary owned copy at
/// production call sites such as `session_glue/mod.rs:1071`.
///
/// Does NOT carry the `ha_activation` flag — that is a control
/// argument to `update_session`, not part of the data payload.
/// `promote_synced_with_origin` hides the flag by calling
/// `update_session(req, false)`.
#[derive(Debug, Clone)]
pub(crate) struct SessionUpdate<'a> {
    pub(crate) key: &'a SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) now_ns: u64,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
}
