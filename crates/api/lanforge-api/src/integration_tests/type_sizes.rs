//! Size budgets for the RPC envelopes: an enum is as large as its largest variant, so one fat
//! inline payload makes every request and response that big. A variant that grows past the
//! budget fails here: box it, or raise the budget on purpose. Sizes are for 64-bit targets.
#![cfg(target_pointer_width = "64")]

use std::mem::size_of;

use crate::api::Response;
use crate::rpc::{RpcRequest, RpcResponse};

#[test]
fn rpc_envelopes_stay_within_their_size_budget() {
    let sizes = [
        ("Response", size_of::<Response>(), 64),
        ("RpcRequest", size_of::<RpcRequest>(), 88),
        ("RpcResponse", size_of::<RpcResponse>(), 64),
    ];
    let over: Vec<String> = sizes
        .iter()
        .filter(|(_, size, budget)| size > budget)
        .map(|(name, size, budget)| format!("{name}: {size} B, budget {budget} B"))
        .collect();
    assert!(
        over.is_empty(),
        "types grew past their budget:\n{}",
        over.join("\n")
    );
}
