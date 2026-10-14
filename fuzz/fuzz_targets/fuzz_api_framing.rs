#![no_main]

use lanforge_api::rpc::{RpcRequest, RpcResponse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Postcard binary deserialization (UDS wire protocol)
    if let Ok(req) = postcard::from_bytes::<RpcRequest>(data)
        && let Ok(re_encoded) = postcard::to_stdvec(&req)
    {
        let _ = postcard::from_bytes::<RpcRequest>(&re_encoded);
    }

    if let Ok(resp) = postcard::from_bytes::<RpcResponse>(data)
        && let Ok(re_encoded) = postcard::to_stdvec(&resp)
    {
        let _ = postcard::from_bytes::<RpcResponse>(&re_encoded);
    }

    // 2. JSON deserialization (HTTP / WebSocket protocol)
    if let Ok(req) = serde_json::from_slice::<RpcRequest>(data)
        && let Ok(json_str) = serde_json::to_string(&req)
    {
        let _ = serde_json::from_str::<RpcRequest>(&json_str);
    }
});
