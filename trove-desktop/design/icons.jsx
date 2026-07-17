// Trove — icon set. Minimal, consistent 1.5px-stroke UI glyphs.
const ICON_PATHS = {
  shield: 'M12 3l7 3v5c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6l7-3z',
  lock: 'M6 10V8a6 6 0 0 1 12 0v2 M5 10h14v10H5z M12 14v3',
  unlock: 'M7 10V8a5 5 0 0 1 9.6-2 M5 10h14v10H5z M12 14v3',
  search: 'M11 11m-7 0a7 7 0 1 0 14 0a7 7 0 1 0 -14 0 M20 20l-4-4',
  plus: 'M12 5v14 M5 12h14',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0',
  eyeOff: 'M3 3l18 18 M10.6 10.6a3 3 0 0 0 4 4 M9.4 5.2A9.8 9.8 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3 3.6 M6.1 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 3.3-.6',
  copy: 'M9 9h10v10H9z M5 15V5h10',
  external: 'M14 5h5v5 M19 5l-8 8 M18 14v5H5V6h5',
  chevron: 'M9 6l6 6-6 6',
  chevronDown: 'M6 9l6 6 6-6',
  key: 'M15 9m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0 M12 12l-8 8 M8 16l2 2 M6 18l2 2',
  globe: 'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0 M3 12h18 M12 3c2.8 3 2.8 15 0 18 M12 3c-2.8 3-2.8 15 0 18',
  cert: 'M6 3h12v18l-6-3-6 3z M9 8h6 M9 11h6',
  db: 'M12 5c4.4 0 8 1.1 8 2.5S16.4 10 12 10 4 8.9 4 7.5 7.6 5 12 5z M4 7.5v9C4 17.9 7.6 19 12 19s8-1.1 8-2.5v-9 M4 12c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5',
  folder: 'M4 6h5l2 2h9v10H4z',
  star: 'M12 4l2.4 5 5.6.6-4 3.8 1 5.6-5-2.8-5 2.8 1-5.6-4-3.8 5.6-.6z',
  x: 'M6 6l12 12 M18 6l-12 12',
  command: 'M9 6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3z',
  enter: 'M20 6v5a3 3 0 0 1-3 3H4 M8 10l-4 4 4 4',
  updown: 'M8 8l4-4 4 4 M8 16l4 4 4-4',
  check: 'M5 12l5 5 9-11',
  edit: 'M4 20h4l10-10-4-4L4 16z M14 6l4 4',
  trash: 'M4 7h16 M9 7V4h6v3 M6 7l1 13h10l1-13',
  clock: 'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0 M12 7v5l3.5 2',
  hash: 'M9 4L7 20 M17 4l-2 16 M4 9h16 M3 15h16',
  gear: 'M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0 M12 3l1 2.5 2.7-.8 .3 2.8 2.8.3-.8 2.7L21 12l-2.5 1 .8 2.7-2.8.3-.3 2.8-2.7-.8L12 21l-1-2.5-2.7.8-.3-2.8-2.8-.3.8-2.7L3 12l2.5-1-.8-2.7 2.8-.3.3-2.8 2.7.8z',
  sun: 'M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0 M12 2v2 M12 20v2 M4 12H2 M22 12h-2 M5 5l1.5 1.5 M17.5 17.5L19 19 M19 5l-1.5 1.5 M6.5 17.5L5 19',
  moon: 'M20 14a8 8 0 1 1-10-10 6 6 0 0 0 10 10z',
  slash: 'M8 20l8-16',
  dots: 'M6 12h.01 M12 12h.01 M18 12h.01',
  file: 'M6 3h8l4 4v14H6z M14 3v4h4',
  refresh: 'M4 12a8 8 0 0 1 14-5l2 2 M20 5v4h-4 M20 12a8 8 0 0 1-14 5l-2-2 M4 19v-4h4',
  chevronsRight: 'M7 6l6 6-6 6 M13 6l6 6-6 6',
  droplet: 'M12 3s6 6.5 6 11a6 6 0 0 1-12 0c0-4.5 6-11 6-11z',
};

function Icon({ name, size = 18, className = "", style }) {
  const d = ICON_PATHS[name];
  if (!d) return null;
  return React.createElement(
    "svg",
    {
      className: "ic " + className,
      width: size, height: size, viewBox: "0 0 24 24",
      fill: "none", stroke: "currentColor",
      strokeWidth: 1.6, strokeLinecap: "round", strokeLinejoin: "round",
      style, "aria-hidden": "true",
    },
    d.split(" M").map((seg, i) =>
      React.createElement("path", { key: i, d: (i === 0 ? seg : "M" + seg) })
    )
  );
}

const TYPE_ICON = { ssh: "key", cert: "cert", db: "db", login: "globe" };

Object.assign(window, { Icon, TYPE_ICON });
