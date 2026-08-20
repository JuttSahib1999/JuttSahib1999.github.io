/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        'cyber': {
          400: '#00e5ff',
          500: '#00bcd4',
          300: '#80deea',
          900: '#001a1f',
        },
        'text': {
          primary: '#e0e0e0',
          secondary: '#b0b0b0',
          muted: '#808080',
        },
        'success': {
          400: '#4caf50',
          500: '#388e3c',
        },
      },
    },
  },
  plugins: [],
}