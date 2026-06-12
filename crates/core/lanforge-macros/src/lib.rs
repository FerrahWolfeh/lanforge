use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parse;
use syn::{
    Data, DeriveInput, Fields, Ident, ItemStruct, ItemTrait, LitStr, Meta, parse_macro_input,
};

/// Attribute macro that automatically implements `LanforgeService` for a struct.
///
/// # Arguments
/// - `id`: The stable identifier for the service (required).
/// - `name`: Human-readable display name (optional, defaults to `id`).
/// - `critical`: Boolean, if true system exits on failure (optional, default: false).
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
    let mut critical = quote! { false };
    let mut retries = quote! { 0 };
    let mut base_backoff = quote! { 1 };
    let mut max_backoff = quote! { 60 };
    let mut stack = quote! { 512 };
    let mut multi_threaded = quote! { false };
    let mut describe = None;

    for meta in args_list {
        if let Meta::NameValue(nv) = meta {
            let val = &nv.value;
            if nv.path.is_ident("id") {
                id = Some(quote! { #val });
            } else if nv.path.is_ident("name") {
                name = Some(quote! { #val });
            } else if nv.path.is_ident("critical") {
                critical = quote! { #val };
            } else if nv.path.is_ident("retries") {
                retries = quote! { #val };
            } else if nv.path.is_ident("base_backoff") {
                base_backoff = quote! { #val };
            } else if nv.path.is_ident("max_backoff") {
                max_backoff = quote! { #val };
            } else if nv.path.is_ident("stack") {
                stack = quote! { #val };
            } else if nv.path.is_ident("multi_threaded") {
                multi_threaded = quote! { #val };
            } else if nv.path.is_ident("describe") {
                describe = Some(quote! { #val });
            }
        }
    }

    let id = id.expect(
        "lanforge_service requires an 'id' argument (e.g., #[lanforge_service(id = \"my-id\")])",
    );
    let display_name = name.unwrap_or_else(|| id.clone());

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
            pub const SERVICE_ID: &'static str = #id;
        }

        impl lanforge_core::service::LanforgeService for #struct_name {
            fn meta(&self) -> lanforge_core::service::ServiceMeta {
                lanforge_core::service::ServiceMeta {
                    id: #id,
                    display_name: #display_name,
                    critical: #critical,
                    max_retries: #retries as u32,
                    base_backoff: std::time::Duration::from_secs(#base_backoff as u64),
                    max_backoff: std::time::Duration::from_secs(#max_backoff as u64),
                    stack_kb: #stack as usize,
                    multi_threaded: #multi_threaded,
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

#[proc_macro_derive(CommandDispatch, attributes(dispatch))]
pub fn command_dispatch_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let variants = if let Data::Enum(data) = input.data {
        data.variants.iter().map(|v| {
            let ident = &v.ident;
            let mut handler = None;
            let mut bus_event = None;
            let mut apply_update = None;
            let mut success_msg = None;
            let mut delegate = false;
            let mut readonly = false;
            let mut args = Vec::new();

            for attr in &v.attrs {
                if attr.path().is_ident("dispatch") {
                    let _ = attr.parse_nested_meta(|meta| {
                        if meta.path.is_ident("handler") {
                            let value: LitStr = meta.value()?.parse()?;
                            handler = Some(value.value());
                        } else if meta.path.is_ident("bus") {
                            let value: LitStr = meta.value()?.parse()?;
                            bus_event = Some(value.value());
                        } else if meta.path.is_ident("apply") {
                            let value: LitStr = meta.value()?.parse()?;
                            apply_update = Some(value.value());
                        } else if meta.path.is_ident("message") {
                            let value: LitStr = meta.value()?.parse()?;
                            success_msg = Some(value.value());
                        } else if meta.path.is_ident("delegate") {
                            delegate = true;
                        } else if meta.path.is_ident("readonly") {
                            readonly = true;
                        } else if meta.path.is_ident("args") {
                            let content;
                            syn::parenthesized!(content in meta.input);
                            let arg_idents = content.parse_terminated(Ident::parse, syn::Token![,])?;
                            args = arg_idents.into_iter().collect();
                        }
                        Ok(())
                    });
                }
            }

            let pattern = match &v.fields {
                Fields::Named(f) => {
                    let used_in_dispatch = bus_event.is_some() || apply_update.is_some();
                    let mut captured = Vec::new();
                    let mut has_unused = false;
                    for field in &f.named {
                        let id = field.ident.as_ref().unwrap();
                        if used_in_dispatch || args.iter().any(|a| a == id) {
                            captured.push(quote! { #id });
                        } else {
                            has_unused = true;
                        }
                    }
                    if has_unused {
                        quote! { { #(#captured),*, .. } }
                    } else {
                        quote! { { #(#captured),* } }
                    }
                }
                Fields::Unnamed(f) => {
                    let idents = (0..f.unnamed.len()).map(|i| Ident::new(&format!("_field_{}", i), ident.span()));
                    quote! { ( #(#idents),* ) }
                }
                Fields::Unit => quote! {},
            };

            if delegate {
                 match &v.fields {
                    Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                        quote! {
                            Self::#ident(_field_0) => _field_0.dispatch(ctx).await,
                        }
                    }
                    _ => quote! {
                        Self::#ident #pattern => crate::api::Response::Error { error: "Invalid delegate".into() },
                    }
                 }
            } else if let Some(h) = handler {
                let h_ident = Ident::new(&h, ident.span());
                let arg_list = args.iter().map(|a| quote! { #a.clone() });
                let log_stmt = if readonly {
                    quote! { tracing::debug!("Dispatching readonly command: {}", stringify!(#ident)); }
                } else {
                    quote! {}
                };
                quote! {
                    Self::#ident #pattern => {
                        #log_stmt
                        ctx.#h_ident(#(#arg_list),*).await
                    },
                }
            } else if let Some(b) = bus_event {
                let b_ident = Ident::new(&b, ident.span());
                let msg = success_msg.unwrap_or_else(|| format!("{} action executed", ident));
                let fields = match &v.fields {
                    Fields::Named(f) => {
                        let f_mappings = f.named.iter().map(|f| {
                           let f_ident = &f.ident;
                           quote! { #f_ident: #f_ident.clone() }
                        });
                        quote! { { #(#f_mappings),* } }
                    },
                    _ => quote! {},
                };

                quote! {
                    Self::#ident #pattern => {
                        let _ = ctx.ctx.bus().publish(lanforge_core::bus::LanforgeEvent::#b_ident #fields);
                        crate::api::Response::Success(crate::api::SimpleSuccess {
                            message: #msg.to_string(),
                        })
                    }
                }
            } else if let Some(a) = apply_update {
                let a_ident = Ident::new(&a, ident.span());
                let msg = success_msg.unwrap_or_else(|| format!("{} update applied", ident));
                
                let fields = match &v.fields {
                    Fields::Named(f) => {
                        let f_mappings = f.named.iter().map(|f| {
                           let f_ident = &f.ident;
                           quote! { #f_ident: #f_ident.clone() }
                        });
                        quote! { { #(#f_mappings),* } }
                    },
                    _ => quote! {},
                };

                quote! {
                    Self::#ident #pattern => {
                        let _ = ctx.ctx.apply(lanforge_core::context::state::DeviceUpdate::#a_ident #fields);
                        crate::api::Response::Success(crate::api::SimpleSuccess {
                            message: #msg.to_string(),
                        })
                    }
                }
            } else {
                quote! {
                    Self::#ident #pattern => crate::api::Response::Error { error: "Unimplemented command".into() },
                }
            }
        }).collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    quote! {
        impl #name {
            pub async fn dispatch(&self, ctx: &crate::server::ClientContext) -> crate::api::Response {
                match self {
                    #(#variants)*
                }
            }
        }
    }.into()
}

/// Derive macro for generating the apply_update dispatch logic in State.
#[proc_macro_derive(UpdateDispatch, attributes(handler))]
pub fn update_dispatch_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let variants =
        if let Data::Enum(data) = input.data {
            data.variants.iter().map(|v| {
            let ident = &v.ident;
            let mut handler_name = None;

            for attr in &v.attrs {
                if attr.path().is_ident("handler")
                    && let Ok(lit) = attr.parse_args::<LitStr>() {
                        handler_name = Some(lit.value());
                    }
            }

            // Fallback: convert VariantName to handle_variant_name
            let h_ident = if let Some(h) = handler_name {
                Ident::new(&h, ident.span())
            } else {
                let snake = to_snake_case(&ident.to_string());
                Ident::new(&format!("handle_{}", snake), ident.span())
            };

            match &v.fields {
                Fields::Named(f) => {
                    let field_names: Vec<_> = f.named.iter().map(|f| &f.ident).collect();
                    quote! {
                        #name::#ident { #(#field_names),* } => self.#h_ident(#(#field_names),*),
                    }
                }
                Fields::Unit => {
                    quote! {
                        #name::#ident => self.#h_ident(),
                    }
                }
                _ => quote! {},
            }
        }).collect::<Vec<_>>()
        } else {
            Vec::new()
        };

    quote! {
        impl State {
            pub fn apply_update(&mut self, update: #name) -> crate::bus::EventVec {
                match update {
                    #(#variants)*
                }
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
                    if let syn::Type::Path(type_path) = &**ty
                        && let Some(segment) = type_path.path.segments.last()
                        && segment.ident == "Result"
                        && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
                    {
                        if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                            is_result = true;
                            inner_type = quote! { #inner };
                        }
                        if args.args.len() > 1
                            && let Some(syn::GenericArgument::Type(err)) = args.args.iter().nth(1)
                        {
                            global_error_type = quote! { #err };
                        }
                    }
                    if !is_result {
                        inner_type = quote! { #ty };
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

        #[async_trait::async_trait]
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

fn to_snake_case(s: &str) -> String {
    let mut snake = String::new();
    for (i, ch) in s.char_indices() {
        if ch.is_uppercase() {
            if i > 0 {
                snake.push('_');
            }
            snake.push(ch.to_ascii_lowercase());
        } else {
            snake.push(ch);
        }
    }
    snake
}

/// Derive macro for generating `ServiceConfig` implementations.
///
/// # Attributes
/// - `#[config(key = "dns")]`: Specifies the TOML section key (required).
#[proc_macro_derive(ServiceConfig, attributes(config))]
pub fn service_config_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let mut key = None;

    for attr in &input.attrs {
        if attr.path().is_ident("config") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("key") {
                    let value: LitStr = meta.value()?.parse()?;
                    key = Some(value.value());
                }
                Ok(())
            });
        }
    }

    let key =
        key.expect("ServiceConfig requires a 'key' attribute (e.g., #[config(key = \"dns\")])");

    quote! {
        impl lanforge_core::config::ServiceConfig for #name {
            const KEY: &'static str = #key;
        }
    }
    .into()
}

/// Derive macro for generating Type, Encode, and Decode implementations for Postgres enums.
///
/// # Attributes
/// - `#[pg_enum(name = "postgres_type_name")]`: Specifies the name of the postgres ENUM type (required).
/// - `#[pg_enum(rename = "custom_name")]`: Renames a variant's db value (optional).
#[proc_macro_derive(PgEnum, attributes(pg_enum))]
pub fn pg_enum_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let mut pg_name = None;

    for attr in &input.attrs {
        if attr.path().is_ident("pg_enum") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    let value: LitStr = meta.value()?.parse()?;
                    pg_name = Some(value.value());
                }
                Ok(())
            });
        }
    }

    let pg_name = pg_name.expect("PgEnum requires a 'name' attribute (e.g., #[pg_enum(name = \"device_origin\")])");

    let mut encode_arms = Vec::new();
    let mut decode_arms = Vec::new();

    if let Data::Enum(data) = input.data {
        for v in &data.variants {
            let ident = &v.ident;
            let mut db_val = ident.to_string().to_lowercase(); // default snake case

            for attr in &v.attrs {
                if attr.path().is_ident("pg_enum") {
                    let _ = attr.parse_nested_meta(|meta| {
                        if meta.path.is_ident("rename") {
                            let value: LitStr = meta.value()?.parse()?;
                            db_val = value.value();
                        }
                        Ok(())
                    });
                }
            }

            encode_arms.push(quote! {
                Self::#ident => #db_val,
            });

            decode_arms.push(quote! {
                #db_val => Ok(Self::#ident),
            });
        }
    }

    quote! {
        impl sqlx::Type<sqlx::Postgres> for #name {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                sqlx::postgres::PgTypeInfo::with_name(#pg_name)
            }
            fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
                ty.name() == #pg_name
            }
        }

        impl<'q> sqlx::Encode<'q, sqlx::Postgres> for #name {
            fn encode_by_ref(&self, buf: &mut sqlx::postgres::PgArgumentBuffer) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
                let s = match self {
                    #(#encode_arms)*
                };
                <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&s, buf)
            }
        }

        impl<'r> sqlx::Decode<'r, sqlx::Postgres> for #name {
            fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
                let s = <&str as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
                match s {
                    #(#decode_arms)*
                    other => Err(format!("Unknown {} variant: {}", stringify!(#name), other).into()),
                }
            }
        }
    }.into()
}
