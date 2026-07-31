// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
  site: 'https://JuttSahib1999.github.io',
  
  integrations: [
    sitemap(),
  ],
  
  vite: {
    plugins: [tailwindcss()],
  },
  
  server: {
    port: 4321,
  },
});