mod biometric;
mod commands;

use commands::{AppState, DatabaseState};
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(DatabaseState::new(AppState::default()))
        .setup(|app| {
            // Before anything reads settings or the database list: the bundle
            // identifier changed, and macOS keys the config directory by it.
            commands::migrate_legacy_config(app.handle());

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
            commands::list_databases,
            commands::register_database,
            commands::create_database,
            commands::unlock_database,
            commands::build_info,
            commands::get_settings,
            commands::set_agent_key,
            commands::set_settings,
            commands::lock_database,
            commands::save_database,
            commands::remove_database,
            commands::list_entries,
            commands::list_groups,
            commands::get_database_metadata,
            commands::set_database_metadata,
            commands::set_group_tags,
            commands::create_group,
            commands::delete_group,
            commands::list_attachments,
            commands::read_attachment,
            commands::read_attachment_image,
            commands::save_attachment,
            commands::attach_file,
            commands::delete_attachment,
            commands::rename_attachment,
            commands::set_attachment_materialize,
            commands::entry_capabilities,
            commands::set_capability_item,
            commands::remove_capability_item,
            commands::set_capability_on,
            commands::group_capabilities,
            commands::set_group_default,
            commands::database_changed_on_disk,
            commands::reload_database,
            commands::database_health,
            commands::get_field,
            commands::get_entry_detail,
            commands::get_entry_revisions,
            commands::list_revision_entries,
            commands::apply_entry_revision,
            commands::set_custom_attribute,
            commands::remove_custom_attribute,
            commands::save_entry,
            commands::delete_entry,
            commands::drop_entry,
            commands::drop_group,
            commands::set_favorite,
            commands::biometric_status,
            commands::biometric_unlock,
            commands::biometric_enroll,
            commands::biometric_forget,
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
