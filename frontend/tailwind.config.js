/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class', // Support toggling class='dark' on html element
  theme: {
    extend: {
      colors: {
        // Custom dark-mode color system
        background: "#090d16",
        card: "#111827",
        border: "#1f2937",
        primary: {
          DEFAULT: "#6366f1", // Indigo
          hover: "#4f46e5",
        },
        accent: {
          DEFAULT: "#06b6d4", // Cyan
        },
        success: "#10b981", // Emerald
        warning: "#f59e0b", // Amber
        danger: "#ef4444", // Rose
        info: "#3b82f6", // Blue
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
    },
  },
  plugins: [],
}
