import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./app/**/*.{js,ts,jsx,tsx,mdx}", "./components/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: { extend: { colors: { brand: "#4338ca", accent: "#f59e0b" }, fontFamily: { mono: ["JetBrains Mono", "Consolas", "monospace"], display: ["Inter", "Arial", "sans-serif"] } } },
  plugins: [],
};
export default config;
