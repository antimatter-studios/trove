mod biometric;
mod commands;
mod daemon_host;

use commands::{AppState, DatabaseState};
use daemon_host::DaemonHost;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager, RunEvent,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(DatabaseState::new(AppState::default()))
        .manage(DaemonHost::new(
            tauri::async_runtime::handle().inner().clone(),
        ))
        .setup(|app| {
            // Before anything reads settings or the database list: the bundle
            // identifier changed, and macOS keys the config directory by it.
            commands::migrate_legacy_config(app.handle());

            // Host the daemon unless one already runs, in which case this app
            // is its client. Off the setup path: the window opens either way,
            // and a failure only shows in Settings.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                handle.state::<DaemonHost>().ensure().await;
            });

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
            commands::daemon_status,
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
            commands::rename_group,
            commands::set_favorite,
            commands::biometric_status,
            commands::biometric_unlock,
            commands::biometric_enroll,
            commands::biometric_forget,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // Quit from the tray, or any normal exit: stop the hosted daemon so
            // its sockets go and the next `trove` command autospawns troved.
            if let RunEvent::Exit = event {
                let host = app.state::<DaemonHost>();
                if !tauri::async_runtime::block_on(host.stop(daemon_host::STOP_TIMEOUT)) {
                    eprintln!("trove-desktop: the hosted daemon did not stop in time");
                }
            }
        });
}

/// Reveal and focus the app's primary window (label-agnostic).
fn reveal<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some((_, w)) = app.webview_windows().iter().next() {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}
