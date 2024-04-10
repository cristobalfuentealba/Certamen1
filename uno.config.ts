import { defineConfig } from 'unocss'

export default defineConfig({
	cli: {
		entry: {
			patterns: ['public/index.html'],
			outFile: 'public/css/uno.css'
		},
	},
	theme: {
		container: {
			center: true,
			padding: '15px'
		}
	}
})