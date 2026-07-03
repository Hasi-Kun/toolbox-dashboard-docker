/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        base: {
          DEFAULT: "#0B1220",
          elevated: "#111A2E",
          border: "#1E293F",
        },
        ink: {
          DEFAULT: "#E7ECF5",
          muted: "#8B96AC",
        },
        signal: {
          DEFAULT: "#35E0C0",
          dim: "#1E8F79",
        },
        warn: "#F5A623",
        critical: "#FF5C5C",
      },
      fontFamily: {
        display: ["var(--font-display)", "sans-serif"],
        body: ["var(--font-body)", "sans-serif"],
        mono: ["var(--font-mono)", "monospace"],
      },
      boxShadow: {
        card: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.5)",
      },
    },
  },
  plugins: [],
};
