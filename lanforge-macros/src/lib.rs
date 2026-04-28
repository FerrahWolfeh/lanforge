use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parse;
use syn::{Data, DeriveInput, Fields, Ident, ItemFn, ItemStruct, LitStr, Meta, parse_macro_input};

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

/// Attribute macro that simplifies device state mutation handlers.
/// Automatically handles: retrieving device, unindexing, mutation, re-indexing, and insertion.
#[proc_macro_attribute]
pub fn device_handler(args: TokenStream, input: TokenStream) -> TokenStream {
    let args_parsed = parse_macro_input!(args as Ident);
    let mac_ident = args_parsed;

    let input_fn = parse_macro_input!(input as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_vis = &input_fn.vis;
    let fn_args = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let fn_block = &input_fn.block;

    let expanded = quote! {
        #fn_vis fn #fn_name(#fn_args) #fn_output {
            let m = #mac_ident;

            let mut dev_arc = match self.devices.remove(&m) {
                Some(d) => d,
                None => std::sync::Arc::new(crate::device::Device::new(m)),
            };

            let result;
            {
                let dev = std::sync::Arc::make_mut(&mut dev_arc);
                self.unindex_device(dev);

                result = (|| {
                    #fn_block
                })();

                self.index_device(m, dev);
            }

            self.devices.insert(m, dev_arc);
            result
        }
    };

    expanded.into()
}

/// Derive macro for generating ProxyUpdate methods in LanforgeContext.
#[proc_macro_derive(ProxyUpdate, attributes(proxy))]
pub fn proxy_update_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let _name = input.ident;

    let variants = if let Data::Enum(data) = input.data {
        data.variants
            .iter()
            .map(|v| {
                let ident = &v.ident;
                let mut method_name = None;

                for attr in &v.attrs {
                    if attr.path().is_ident("proxy") {
                        let _ = attr.parse_nested_meta(|meta| {
                            if meta.path.is_ident("method") {
                                let value: LitStr = meta.value()?.parse()?;
                                method_name = Some(value.value());
                            }
                            Ok(())
                        });
                    }
                }

                if let Some(m) = method_name {
                    let m_ident = Ident::new(&m, ident.span());

                    match &v.fields {
                        Fields::Named(f) => {
                            let f_idents = f.named.iter().map(|f| &f.ident);
                            let f_types = f.named.iter().map(|f| &f.ty);
                            let f_clones = f.named.iter().map(|f| {
                                let id = &f.ident;
                                quote! { #id: #id.clone() }
                            });
                            quote! {
                                /// Automatically generated proxy for DeviceUpdate variant.
                                #[must_use]
                                pub fn #m_ident(&self, #(#f_idents: #f_types),*) -> bool {
                                    self.apply(&DeviceUpdate::#ident { #(#f_clones),* })
                                }
                            }
                        }
                        Fields::Unit => {
                            quote! {
                                /// Automatically generated proxy for DeviceUpdate variant.
                                pub fn #m_ident(&self) {
                                    let _ = self.apply(&DeviceUpdate::#ident);
                                }
                            }
                        }
                        _ => quote! {},
                    }
                } else {
                    quote! {}
                }
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    quote! {
        impl LanforgeContext {
            #(#variants)*
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
                        let _ = ctx.ctx.apply(&lanforge_core::context::state::DeviceUpdate::#a_ident #fields);
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

#[proc_macro_derive(CliHandler, attributes(handler))]
pub fn cli_handler_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let variants = if let Data::Enum(data) = input.data {
        data.variants.iter().map(|v| {
            let ident = &v.ident;
            let mut handler_expr = None;

            for attr in &v.attrs {
                if attr.path().is_ident("handler") {
                    let _ = attr.parse_nested_meta(|meta| {
                        if meta.path.is_ident("generic") {
                            let content;
                            syn::parenthesized!(content in meta.input);
                            let action: Ident = content.parse()?;
                            
                            let mut action_fields = quote! {};
                            if content.peek(syn::Token![,]) {
                                content.parse::<syn::Token![,]>()?;
                                if content.peek(syn::token::Brace) {
                                    let fields_content;
                                    syn::braced!(fields_content in content);
                                    let fields = fields_content.parse_terminated(Ident::parse, syn::Token![,])?;
                                    let field_mappings = fields.iter().map(|f| quote! { #f: #f.clone() });
                                    action_fields = quote! { { #(#field_mappings),* } };
                                }
                            }
                            
                            content.parse::<syn::Token![,]>()?;
                            let streaming: syn::LitBool = content.parse()?;
                            
                            handler_expr = Some(quote! {
                                Box::new(crate::cli::commands::GenericHandler {
                                    cmd: lanforge_api::api::Command::new(lanforge_api::api::CommandAction::#action #action_fields),
                                    streaming: #streaming,
                                })
                            });
                        } else {
                            // Assume it's a struct name
                            let handler_name = meta.path.get_ident().cloned().unwrap();
                            let mut copy_fields = false;
                            
                            if meta.input.peek(syn::token::Brace) {
                                let content;
                                syn::braced!(content in meta.input);
                                if content.peek(syn::Token![..]) {
                                    content.parse::<syn::Token![..]>()?;
                                    copy_fields = true;
                                }
                            }

                            let fields = match &v.fields {
                                Fields::Named(f) if copy_fields => {
                                    let idents = f.named.iter().map(|f| &f.ident);
                                    quote! { { #(#idents: #idents.clone()),* } }
                                }
                                _ => quote! {},
                            };

                            handler_expr = Some(quote! {
                                Box::new(crate::cli::commands::#handler_name #fields)
                            });
                        }
                        Ok(())
                    });
                }
            }

            let pattern = match &v.fields {
                Fields::Named(f) => {
                    let field_names = f.named.iter().map(|f| &f.ident);
                    quote! { { #(#field_names),* } }
                }
                Fields::Unnamed(_) => quote! { ( .. ) },
                Fields::Unit => quote! {},
            };

            let expr = handler_expr.unwrap_or_else(|| {
                quote! { unreachable!("Missing handler for variant {}", stringify!(#ident)) }
            });

            quote! {
                Self::#ident #pattern => #expr,
            }
        }).collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    quote! {
        impl #name {
            pub fn to_handler(&self) -> Box<dyn crate::cli::commands::CliCommand> {
                match self {
                    #(#variants)*
                }
            }
        }
    }
    .into()
}
