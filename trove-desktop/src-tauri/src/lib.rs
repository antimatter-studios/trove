mod commands;

use commands::{AppState, VaultState};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(VaultState::new(AppState::default()))
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
