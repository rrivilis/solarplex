use tauri::Manager;
use tauri_plugin_deep_link::DeepLinkExt;

/// Pulls `sp_token` out of a `solarplex-desktop://auth#sp_token=...` (or
/// `?sp_token=...`) deep-link URL. Deliberately a plain substring search
/// rather than a full URL/query parse — the token is the only thing this
/// scheme ever carries and is itself a plain ULID (no characters that need
/// percent-decoding), so a parser is more moving parts than the value
/// extracted is worth.
fn extract_sp_token(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once('#').or_else(|| url.split_once('?'))?;
    rest.split('&')
        .find_map(|kv| kv.strip_prefix("sp_token="))
        .filter(|t| !t.is_empty())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .plugin(tauri_plugin_opener::init())
    .plugin(tauri_plugin_deep_link::init())
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }

      // Windows/Linux register their custom-scheme handler via the OS
      // installer at bundle time; a `cargo run`/`tauri dev` binary has no
      // installer, so register_all() points the OS at *this* exe's exact
      // path for the schemes declared in tauri.conf.json instead. No-op
      // (and unneeded) on macOS, where Info.plist covers both dev and
      // bundled builds.
      #[cfg(any(windows, target_os = "linux"))]
      app.deep_link().register_all()?;

      // The desktop sign-in flow (frontend/lib/auth.ts's signIn(), gated on
      // isTauri()) opens OIDC in the system browser instead of this app's
      // own webview — see crates/server/src/auth.rs's PkceEntry::desktop doc
      // comment for why. The provider's callback lands back here as a
      // solarplex-desktop://auth#sp_token=... deep link; forward the token
      // into the webview by navigating it to the same hash-fragment shape
      // frontend/lib/auth.ts's captureSpTokenFromHash() already expects from
      // the ordinary in-browser flow, so no separate desktop-only capture
      // path is needed on the frontend side.
      let handle = app.handle().clone();
      app.deep_link().on_open_url(move |event| {
        let Some(window) = handle.get_webview_window("main") else { return };
        for url in event.urls() {
          if let Some(token) = extract_sp_token(&url.to_string()) {
            let js = format!("window.location.href = '/#sp_token={token}';");
            let _ = window.eval(&js);
          }
        }
      });

      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
