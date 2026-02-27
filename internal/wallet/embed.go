package wallet

import "embed"

//go:embed static/index.html static/app.js static/style.css
var staticFiles embed.FS
