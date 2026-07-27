mod commands;

use commands::{AppState, VaultState};
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(VaultState::new(AppState::default()))
        .setup(|app| {
            // System tray: the Trove icon in the menu bar / system tray, with a
            // small menu. Additive — it does not change the window's close
            // behavior. Uses the app's own window icon so it tracks the bundle.
            let show = MenuItem::with_id(app, "show", "Show Trove", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit Trove", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .tooltip("Trove")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => reveal(app),
                    "quit" => app.exit(0),
                    _ => {}
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_vaults,
            commands::register_vault,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::list_entries,
            commands::get_field,
            commands::get_entry_detail,
            commands::save_entry,
            commands::delete_entry,
            commands::set_favorite,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Reveal and focus the app's primary window (label-agnostic).
fn reveal<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some((_, w)) = app.webview_windows().iter().next() {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}
