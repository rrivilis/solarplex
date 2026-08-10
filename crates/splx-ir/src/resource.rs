//! Mirrors the six resource classes in `sp-dsl/src/ir.lisp`. serializer.lisp
//! tags each as `(:fs ...)`, `(:net ...)`, `(:pid ...)`, `(:ipc-fd ...)`,
//! `(:http ...)`, `(:wasm ...)` — a plain `(:tag ...)` list, not wrapped in
//! an outer `:resource` tag, so `Resource::from_value` dispatches on the
//! tag directly rather than going through `TaggedList`'s generic path.

use lexpr::Value;

use crate::parse::{is_lisp_nil, require_i64, require_str, AnyOrInt, IrError};
use crate::algebra::OpSet;

#[derive(Debug, Clone, PartialEq)]
pub enum Resource {
    Fs { path: String },
    Net { host: String, port_min: i64, port_max: i64, path_prefix: String },
    Pid { pid_ref: AnyOrInt },
    IpcFd { fd: AnyOrInt },
    Http { url_pattern: String, methods: Option<OpSet> },
    Wasm { module: String },
}

impl Resource {
    pub fn provider(&self) -> &'static str {
        match self {
            Resource::Fs { .. } => "linux-fs",
            Resource::Net { .. } => "linux-net",
            Resource::Pid { .. } => "linux-pid",
            Resource::IpcFd { .. } => "ipc-fd",
            Resource::Http { .. } => "http-ucan",
            Resource::Wasm { .. } => "wasm",
        }
    }

    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        let list = crate::parse::TaggedList::parse(v)?;
        match list.tag {
            "fs" => Ok(Resource::Fs {
                path: require_str(list.require("path")?, "path")?.to_string(),
            }),
            "net" => Ok(Resource::Net {
                host: require_str(list.require("host")?, "host")?.to_string(),
                port_min: list.get("port-min").map(|v| require_i64(v, "port-min")).transpose()?.unwrap_or(0),
                port_max: list.get("port-max").map(|v| require_i64(v, "port-max")).transpose()?.unwrap_or(65535),
                path_prefix: list
                    .get("path-prefix")
                    .map(|v| require_str(v, "path-prefix").map(str::to_string))
                    .transpose()?
                    .unwrap_or_else(|| "/".to_string()),
            }),
            "pid" => Ok(Resource::Pid { pid_ref: AnyOrInt::from_value(list.require("ref")?)? }),
            "ipc-fd" => Ok(Resource::IpcFd { fd: AnyOrInt::from_value(list.require("fd")?)? }),
            "http" => Ok(Resource::Http {
                url_pattern: require_str(list.require("url")?, "url")?.to_string(),
                methods: match list.get("methods") {
                    Some(v) if !is_lisp_nil(v) => Some(OpSet::from_value(v)?),
                    _ => None,
                },
            }),
            "wasm" => Ok(Resource::Wasm {
                module: require_str(list.require("module")?, "module")?.to_string(),
            }),
            other => Err(IrError::WrongTag { expected: "fs|net|pid|ipc-fd|http|wasm", actual: other.to_string() }),
        }
    }
}
