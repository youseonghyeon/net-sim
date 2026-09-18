import type { JSX } from "preact";

export type IconName =
  | "pc"
  | "laptop"
  | "server"
  | "switch"
  | "router"
  | "internet"
  | "cursor"
  | "cable"
  | "sun"
  | "moon"
  | "plus"
  | "trash"
  | "chevron"
  | "mark"
  | "play"
  | "pause"
  | "step"
  | "refresh"
  | "send";

const PATHS: Record<IconName, JSX.Element> = {
  pc: (
    <>
      <rect x="3" y="4.5" width="18" height="12" rx="2" />
      <path d="M12 16.5v3M8.5 19.5h7" />
    </>
  ),
  laptop: (
    <>
      <rect x="4.5" y="5" width="15" height="10" rx="1.5" />
      <path d="M2 18.5h20" />
    </>
  ),
  server: (
    <>
      <rect x="3.5" y="3.5" width="17" height="5" rx="1.2" />
      <rect x="3.5" y="9.5" width="17" height="5" rx="1.2" />
      <rect x="3.5" y="15.5" width="17" height="5" rx="1.2" />
      <path d="M7 6h.01M7 12h.01M7 18h.01" stroke-width="2" />
    </>
  ),
  switch: (
    <>
      <rect x="2.5" y="8" width="19" height="8" rx="2" />
      <path d="M6.5 10.5h5l-1.6-1.6M11.5 10.5 9.9 12.1M17.5 13.5h-5l1.6-1.6M12.5 13.5l1.6 1.6" />
    </>
  ),
  router: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M8 9.5h8l-2.2-2.2M16 9.5l-2.2 2.2M16 14.5H8l2.2-2.2M8 14.5l2.2 2.2" />
    </>
  ),
  internet: <path d="M7 18.5a4 4 0 0 1-.6-7.95A5.5 5.5 0 0 1 17 9.5a3.5 3.5 0 0 1 .5 6.96V18.5z" />,
  cursor: <path d="M5.5 3.5 19 10.5l-6 1.5-3 6z" />,
  cable: (
    <>
      <path d="M4 20l5.5-5.5M14.5 9.5 20 4" />
      <path d="M8 12.5 11.5 16 16 11.5 12.5 8z" />
      <path d="M10 10l-1.5-1.5M14 14l1.5 1.5" />
    </>
  ),
  sun: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4" />
    </>
  ),
  moon: <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z" />,
  plus: <path d="M12 5v14M5 12h14" />,
  trash: <path d="M4 7h16M9.5 7V4.5h5V7M6.5 7l.8 12.5h9.4L17.5 7M10 11v5M14 11v5" />,
  chevron: <path d="M6 9l6 6 6-6" />,
  mark: (
    <>
      <circle cx="6" cy="17" r="2.5" />
      <circle cx="18" cy="17" r="2.5" />
      <circle cx="12" cy="6" r="2.5" />
      <path d="M8 15.5 10.5 8M16 15.5 13.5 8M8.5 17h7" />
    </>
  ),
  play: <path d="M7 4.5v15l12-7.5z" fill="currentColor" stroke="none" />,
  pause: <path d="M7 5h3.5v14H7zM13.5 5H17v14h-3.5z" fill="currentColor" stroke="none" />,
  step: (
    <>
      <path d="M5 5v14l10-7z" fill="currentColor" stroke="none" />
      <path d="M18 5v14" stroke-width="2" />
    </>
  ),
  refresh: <path d="M20 12a8 8 0 1 1-2.3-5.6M20 4v5h-5" />,
  send: <path d="M4 12h15M13 6l6 6-6 6" />,
};

export function Icon({ name, size = 20, class: cls }: { name: IconName; size?: number; class?: string }) {
  return (
    <svg
      class={cls}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      {PATHS[name]}
    </svg>
  );
}

/** 캔버스(SVG 내부)용: <g> 로 감싼 아이콘. 24×24 좌표계를 size 로 스케일 */
export function GlyphInSvg({ name, x, y, size }: { name: IconName; x: number; y: number; size: number }) {
  const s = size / 24;
  return (
    <g transform={`translate(${x},${y}) scale(${s})`} fill="none" stroke="currentColor" stroke-width={1.6} stroke-linecap="round" stroke-linejoin="round">
      {PATHS[name]}
    </g>
  );
}
