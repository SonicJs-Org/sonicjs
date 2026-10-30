/** @type {import('prettier').Options} */
export default {
  singleQuote: true,
  semi: false,
  plugins: ['prettier-plugin-organize-imports', 'prettier-plugin-tailwindcss'],
  tailwindStylesheet: './src/styles/tailwind.css',
}
