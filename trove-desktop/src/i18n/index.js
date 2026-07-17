// i18next bootstrap with auto-discovery of locale catalogs.
//
// Drop a new `./locales/<code>.json` and it becomes available automatically
// (Vite's import.meta.glob bundles them at build time). Each catalog must
// expose `language.name` so a picker can render its own native label.
//
// Language preference is persisted to localStorage only — trove-desktop has no
// settings backend yet. When one lands, hydrate from it here (see diskcutter's
// config_get/config_set pattern for reference).

import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

const modules = import.meta.glob('./locales/*.json', { eager: true });

const resources = {};
const available = [];

for (const [path, mod] of Object.entries(modules)) {
  const match = path.match(/\.\/locales\/([^/]+)\.json$/);
  if (!match) continue;
  const code = match[1];
  const data = mod.default || mod;
  resources[code] = { translation: data };
  available.push({
    code,
    name: (data && data.language && data.language.name) || code,
  });
}

available.sort((a, b) => a.name.localeCompare(b.name));

const STORAGE_KEY = 'trove.language';

function pickInitialLanguage() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && resources[saved]) return saved;
  } catch {
    // localStorage may throw in restrictive contexts; fall through.
  }
  if (typeof navigator !== 'undefined' && navigator.language) {
    const primary = navigator.language.toLowerCase();
    if (resources[primary]) return primary;
    const short = primary.split('-')[0];
    if (resources[short]) return short;
  }
  if (resources.en) return 'en';
  return available[0]?.code || 'en';
}

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: pickInitialLanguage(),
    fallbackLng: 'en',
    interpolation: { escapeValue: false },
    returnEmptyString: false,
  });

i18n.on('languageChanged', (lng) => {
  try {
    localStorage.setItem(STORAGE_KEY, lng);
  } catch {
    // ignore — preference is best-effort
  }
});

export { available as availableLanguages };
export default i18n;
