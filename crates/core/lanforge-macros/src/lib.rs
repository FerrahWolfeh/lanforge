use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Ident, ItemStruct, ItemTrait, LitStr, Meta, parse_macro_input};

/// Attribute macro that automatically implements `LanforgeService` for a struct.
///
/// # Arguments
/// - `id`: The stable identifier for the service (required).
/// - `name`: Human-readable display name (optional, defaults to `id`).
/// - `retries`: Max restart attempts, 0 for infinite (optional, default: 0).
/// - `base_backoff`: Initial backoff in seconds (optional, default: 1).
/// - `max_backoff`: Maximum backoff cap in seconds (optional, default: 60).
/// - `stack`: Stack size for sync service thread in KB (optional, default: 512).
/// - `describe`: Custom expression for the `describe()` method (optional).
#[proc_macro_attribute]
pub fn lanforge_service(args: TokenStream, input: TokenStream) -> TokenStream {
    let args_list = parse_macro_input!(args with syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated);
    let input_struct = parse_macro_input!(input as ItemStruct);
    let struct_name = &input_struct.ident;

    let mut id = None;
    let mut name = None;
    let mut retries = quote! { 0 };
    let mut base_backoff = quote! { 1 };
    let mut max_backoff = quote! { 60 };
    let mut shutdown_timeout = quote! { 3 };
    let mut multi_threaded = quote! { false };
    let mut runtime_class = None;
    let mut describe = None;

    for meta in args_list {
        if let Meta::NameValue(nv) = meta {
            let val = &nv.value;
            if nv.path.is_ident("id") {
                id = Some(val.clone());
            } else if nv.path.is_ident("name") {
                name = Some(quote! { #val });
            } else if nv.path.is_ident("retries") {
                retries = quote! { #val };
            } else if nv.path.is_ident("base_backoff") {
                base_backoff = quote! { #val };
            } else if nv.path.is_ident("max_backoff") {
                max_backoff = quote! { #val };
            } else if nv.path.is_ident("shutdown_timeout")
                || nv.path.is_ident("shutdown_timeout_secs")
            {
                shutdown_timeout = quote! { #val };
            } else if nv.path.is_ident("multi_threaded") {
                multi_threaded = quote! { #val };
            } else if nv.path.is_ident("runtime") {
                runtime_class = Some(quote! { #val });
            } else if nv.path.is_ident("describe") {
                describe = Some(quote! { #val });
            } else {
                return syn::Error::new_spanned(&nv.path, "unknown lanforge_service attribute")
                    .to_compile_error()
                    .into();
            }
        }
    }

    let runtime_expr = if let Some(rc) = runtime_class {
        quote! {
            if #rc == "dedicated" {
                lanforge_core::service::RuntimeClass::Dedicated {
                    multi_thread: #multi_threaded,
                    worker_threads: None,
                }
            } else {
                lanforge_core::service::RuntimeClass::Shared
            }
        }
    } else {
        quote! {
            if #multi_threaded {
                lanforge_core::service::RuntimeClass::Dedicated {
                    multi_thread: true,
                    worker_threads: None,
                }
            } else {
                lanforge_core::service::RuntimeClass::Shared
            }
        }
    };

    let id_expr = id.expect(
        "lanforge_service requires an 'id' argument (e.g., #[lanforge_service(id = \"db\")])",
    );
    let id_str = match &id_expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) => s.value(),
        syn::Expr::Path(p) => p
            .path
            .segments
            .last()
            .map(|seg| seg.ident.to_string())
            .unwrap_or_default(),
        _ => quote!(#id_expr).to_string(),
    };

    let (service_id_variant, default_name) = match id_str.trim().to_ascii_lowercase().as_str() {
        "db" | "database" => (quote! { lanforge_types::system::ServiceId::Db }, "Database"),
        "nft" | "firewall" | "nftables" => (
            quote! { lanforge_types::system::ServiceId::Nft },
            "Firewall",
        ),
        "pppoe" => (quote! { lanforge_types::system::ServiceId::Pppoe }, "PPPoE"),
        "dns" => (quote! { lanforge_types::system::ServiceId::Dns }, "DNS"),
        "dhcp4" | "dhcp_v4" | "dhcpv4" => (
            quote! { lanforge_types::system::ServiceId::Dhcp4 },
            "DHCPv4",
        ),
        "dhcp6" | "dhcp_v6" | "dhcpv6" => (
            quote! { lanforge_types::system::ServiceId::Dhcp6 },
            "DHCPv6",
        ),
        "ra" | "radvd" => (
            quote! { lanforge_types::system::ServiceId::Ra },
            "IPv6 Router Advertisements",
        ),
        "traffic" | "sqm" => (
            quote! { lanforge_types::system::ServiceId::Traffic },
            "Traffic & SQM",
        ),
        "tftp" => (quote! { lanforge_types::system::ServiceId::Tftp }, "TFTP"),
        "discovery" | "monitor" | "ndp" => (
            quote! { lanforge_types::system::ServiceId::Discovery },
            "Network Discovery",
        ),
        "mdns" => (quote! { lanforge_types::system::ServiceId::Mdns }, "mDNS"),
        "http" | "web" => (
            quote! { lanforge_types::system::ServiceId::Http },
            "HTTP API",
        ),
        "uds" | "control" => (
            quote! { lanforge_types::system::ServiceId::Uds },
            "Control Socket",
        ),
        other => panic!("Unknown service id: {other}"),
    };

    let display_name = name.unwrap_or_else(|| quote! { #default_name });

    let describe_method = if let Some(expr) = describe {
        quote! {
            fn describe(&self) -> String {
                #expr
            }
        }
    } else {
        quote! {}
    };

    let expanded = quote! {
        #input_struct

        impl #struct_name {
            /// Static identifier for the service.
            pub const SERVICE_ID: lanforge_types::system::ServiceId = #service_id_variant;
        }

        impl lanforge_core::service::LanforgeService for #struct_name {
            fn spec(&self) -> lanforge_core::service::ServiceSpec {
                lanforge_core::service::ServiceSpec {
                    id: Self::SERVICE_ID,
                    display_name: #display_name,
                    runtime: #runtime_expr,
                    restart: lanforge_core::service::RestartPolicy {
                        base_backoff: std::time::Duration::from_secs(#base_backoff as u64),
                        max_backoff: std::time::Duration::from_secs(#max_backoff as u64),
                        max_retries: #retries as u32,
                        healthy_uptime: if matches!(Self::SERVICE_ID, lanforge_types::system::ServiceId::Pppoe) {
                            std::time::Duration::from_secs(60)
                        } else {
                            std::time::Duration::from_secs(30)
                        },
                    },
                    shutdown_timeout: std::time::Duration::from_secs(#shutdown_timeout as u64),
                    deps: &[],
                    condition: lanforge_core::service::Condition::ALWAYS,
                }
            }

            #describe_method
        }
    };

    expanded.into()
}

/// Derive macro for enums that provides string representation logic.
#[proc_macro_derive(EnumRepr, attributes(enum_repr))]
pub fn enum_repr_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let mut as_str_arms = Vec::new();
    let mut from_str_arms = Vec::new();

    if let Data::Enum(data) = input.data {
        for v in &data.variants {
            let ident = &v.ident;
            let mut repr = ident.to_string().to_lowercase();
            let mut aliases = Vec::new();

            for attr in &v.attrs {
                if attr.path().is_ident("enum_repr") {
                    let _ = attr.parse_nested_meta(|meta| {
                        if meta.path.is_ident("rename") {
                            let value: LitStr = meta.value()?.parse()?;
                            repr = value.value();
                        } else if meta.path.is_ident("alias") {
                            let value: LitStr = meta.value()?.parse()?;
                            aliases.push(value.value());
                        }
                        Ok(())
                    });
                }
            }

            as_str_arms.push(quote! {
                Self::#ident { .. } => #repr,
            });

            from_str_arms.push(quote! {
                #repr => Ok(Self::#ident),
            });
            for alias in aliases {
                from_str_arms.push(quote! {
                    #alias => Ok(Self::#ident),
                });
            }
        }
    }

    quote! {
        impl #name {
            pub fn as_str(&self) -> &'static str {
                match self {
                    #(#as_str_arms)*
                }
            }
        }

        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }

        impl std::str::FromStr for #name {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s.to_lowercase().as_str() {
                    #(#from_str_arms)*
                    _ => Err(format!("Invalid variant: {}", s)),
                }
            }
        }
    }
    .into()
}

/// Derive macro for generating Display, Debug, and Serde implementations for identifiers.
#[proc_macro_derive(Identifier)]
pub fn identifier_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    quote! {
        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let bytes = self.as_bytes();
                for (i, b) in bytes.iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }

        impl std::fmt::Debug for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!(#name), self.to_string())
            }
        }

        impl serde::Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> serde::Deserialize<'de> for #name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                use std::str::FromStr;
                Self::from_str(&s).map_err(serde::de::Error::custom)
            }
        }
    }
    .into()
}

#[proc_macro_attribute]
pub fn lanforge_rpc(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input_trait = parse_macro_input!(input as ItemTrait);
    let trait_name = &input_trait.ident;

    let mut request_variants = Vec::new();
    let mut response_variants = Vec::new();
    let mut dispatch_arms = Vec::new();
    let mut client_methods = Vec::new();
    let mut global_error_type = quote! { String };

    for item in &input_trait.items {
        if let syn::TraitItem::Fn(method) = item {
            let method_name = &method.sig.ident;
            let variant_name = Ident::new(
                &to_pascal_case(&method_name.to_string()),
                method_name.span(),
            );

            let mut args = Vec::new();
            let mut arg_names = Vec::new();

            for arg in &method.sig.inputs {
                if let syn::FnArg::Typed(pat_type) = arg
                    && let syn::Pat::Ident(pat_ident) = &*pat_type.pat
                {
                    let arg_name = &pat_ident.ident;
                    let arg_type = &pat_type.ty;
                    args.push(quote! { #arg_name: #arg_type });
                    arg_names.push(arg_name);
                }
            }

            let mut is_result = false;
            let mut inner_type = quote! { () };

            match &method.sig.output {
                syn::ReturnType::Default => {}
                syn::ReturnType::Type(_, ty) => {
                    let (is_res, inner, err) = extract_rpc_return_type(ty);
                    is_result = is_res;
                    inner_type = quote! { #inner };
                    if let Some(e) = err {
                        global_error_type = quote! { #e };
                    }
                }
            };

            request_variants.push(quote! {
                #variant_name { #(#args),* }
            });

            response_variants.push(quote! {
                #variant_name(#inner_type)
            });

            if is_result {
                dispatch_arms.push(quote! {
                    RpcRequest::#variant_name { #(#arg_names),* } => {
                        match self.#method_name(#(#arg_names),*).await {
                            Ok(res) => RpcResponse::#variant_name(res),
                            Err(e) => RpcResponse::Error(e),
                        }
                    }
                });
            } else {
                dispatch_arms.push(quote! {
                    RpcRequest::#variant_name { #(#arg_names),* } => {
                        let res = self.#method_name(#(#arg_names),*).await;
                        RpcResponse::#variant_name(res)
                    }
                });
            }

            client_methods.push(quote! {
                #[allow(clippy::too_many_arguments)]
                pub async fn #method_name(&mut self, #(#args),*) -> Result<#inner_type, LanforgeRpcError<#global_error_type>> {
                    let req = RpcRequest::#variant_name { #(#arg_names),* };
                    match self.call(req).await? {
                        RpcResponse::#variant_name(res) => Ok(res),
                        RpcResponse::Error(e) => Err(LanforgeRpcError::Remote(e)),
                        _ => Err(LanforgeRpcError::ProtocolMismatch),
                    }
                }
            });
        }
    }

    let expanded = quote! {
        #input_trait

        #[derive(serde::Serialize, serde::Deserialize, Debug)]
        pub enum RpcRequest {
            #(#request_variants),*
        }

        #[derive(serde::Serialize, serde::Deserialize, Debug)]
        pub enum RpcResponse {
            #(#response_variants),*,
            Event(lanforge_types::events::TimedEvent),
            Error(#global_error_type),
        }

        pub trait LanforgeRpcDispatcher: #trait_name {
            async fn dispatch(&self, req: RpcRequest) -> RpcResponse {
                match req {
                    #(#dispatch_arms)*
                }
            }
        }

        impl<T: #trait_name + Send + Sync> LanforgeRpcDispatcher for T {}

        pub struct LanforgeRpcClient<S> {
            stream: S,
            buffer: Vec<u8>,
        }

        #[derive(thiserror::Error, Debug)]
        pub enum LanforgeRpcError<E> {
            #[error("IO error: {0}")]
            Io(#[from] std::io::Error),
            #[error("Serialization error: {0}")]
            Serialization(String),
            #[error("Remote error: {0}")]
            Remote(E),
            #[error("Protocol mismatch")]
            ProtocolMismatch,
        }

        impl<S> LanforgeRpcClient<S>
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        {
            pub fn new(stream: S) -> Self {
                Self {
                    stream,
                    buffer: Vec::with_capacity(8192),
                }
            }

            async fn call(&mut self, req: RpcRequest) -> Result<RpcResponse, LanforgeRpcError<#global_error_type>> {
                use tokio::io::AsyncWriteExt;

                let mut buffer = std::mem::take(&mut self.buffer);
                buffer.clear();
                let buffer = postcard::to_extend(&req, buffer)
                    .map_err(|e| LanforgeRpcError::Serialization(e.to_string()))?;
                let len = buffer.len() as u32;
                self.buffer = buffer;

                self.stream.write_all(&len.to_be_bytes()).await?;
                self.stream.write_all(&self.buffer).await?;
                self.stream.flush().await?;

                self.next_response().await
            }

            pub async fn next_response(&mut self) -> Result<RpcResponse, LanforgeRpcError<#global_error_type>> {
                use tokio::io::AsyncReadExt;
                let mut len_bytes = [0u8; 4];
                self.stream.read_exact(&mut len_bytes).await?;
                let resp_len = u32::from_be_bytes(len_bytes) as usize;

                self.buffer.resize(resp_len, 0);
                self.stream.read_exact(&mut self.buffer).await?;

                let resp: RpcResponse = postcard::from_bytes(&self.buffer)
                    .map_err(|e| LanforgeRpcError::Serialization(e.to_string()))?;

                Ok(resp)
            }

            #(#client_methods)*
        }
    };

    expanded.into()
}

fn to_pascal_case(s: &str) -> String {
    let mut pascal = String::new();
    let mut capitalize = true;
    for ch in s.chars() {
        if ch == '_' {
            capitalize = true;
        } else if capitalize {
            pascal.push(ch.to_ascii_uppercase());
            capitalize = false;
        } else {
            pascal.push(ch);
        }
    }
    pascal
}

fn extract_rpc_return_type(ty: &syn::Type) -> (bool, syn::Type, Option<syn::Type>) {
    if let Some((inner, err)) = try_extract_result(ty) {
        return (true, inner, Some(err));
    }

    if let syn::Type::ImplTrait(impl_trait) = ty {
        for bound in &impl_trait.bounds {
            if let syn::TypeParamBound::Trait(trait_bound) = bound
                && let Some(last_seg) = trait_bound.path.segments.last()
                && last_seg.ident == "Future"
                && let syn::PathArguments::AngleBracketed(args) = &last_seg.arguments
            {
                for arg in &args.args {
                    if let syn::GenericArgument::AssocType(assoc_type) = arg
                        && assoc_type.ident == "Output"
                    {
                        if let Some((inner, err)) = try_extract_result(&assoc_type.ty) {
                            return (true, inner, Some(err));
                        } else {
                            return (false, assoc_type.ty.clone(), None);
                        }
                    }
                }
            }
        }
    }

    (false, ty.clone(), None)
}

fn try_extract_result(ty: &syn::Type) -> Option<(syn::Type, syn::Type)> {
    if let syn::Type::Path(type_path) = ty
        && let Some(last_seg) = type_path.path.segments.last()
        && last_seg.ident == "Result"
        && let syn::PathArguments::AngleBracketed(args) = &last_seg.arguments
    {
        if args.args.len() >= 2 {
            let first = args.args.first()?;
            let second = args.args.iter().nth(1)?;
            if let (syn::GenericArgument::Type(inner), syn::GenericArgument::Type(err)) =
                (first, second)
            {
                return Some((inner.clone(), err.clone()));
            }
        } else if args.args.len() == 1 {
            let first = args.args.first()?;
            if let syn::GenericArgument::Type(inner) = first {
                return Some((inner.clone(), syn::parse_quote! { String }));
            }
        }
    }
    None
}
