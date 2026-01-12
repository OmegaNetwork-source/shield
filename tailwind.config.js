/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                'tech-black': '#050505',
                'tech-slate': '#0f172a',
                'tech-cyan': '#06b6d4',
                'tech-terminal': '#22c55e',
            }
        },
    },
    plugins: [],
}
