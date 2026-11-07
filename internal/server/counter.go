// The old-school "you are visitor #000123" image.

package server

import (
	"fmt"
	"strconv"
	"strings"
)

// counterDigits is the zero-padded width of the counter.
const counterDigits = 6

const (
	cellW = 16
	cellH = 24
	pad   = 2
)

// counterSVG renders n as green digits in black boxes.
func counterSVG(n int64) []byte {
	digits := fmt.Sprintf("%0*d", counterDigits, max(n, 0))
	w := len(digits)*(cellW+pad) + pad
	h := cellH + 2*pad
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s visitors">`,
		w, h, w, h, strconv.FormatInt(n, 10))
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#000"/>`, w, h)
	for i, d := range digits {
		x := pad + i*(cellW+pad)
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" fill="#111" stroke="#444"/>`, x, pad, cellW, cellH)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-family="'Courier New',monospace" font-size="20" font-weight="bold" fill="#3f3" text-anchor="middle">%c</text>`,
			x+cellW/2, pad+cellH-6, d)
	}
	b.WriteString(`</svg>`)
	return []byte(b.String())
}

// counterJS is a snippet a page can include with
//
//	<script src="https://collector/counter.js" data-site="blog"></script>
//
// It drops the counter image right where the script tag is.
const counterJS = `(function () {
  var s = document.currentScript;
  if (!s) return;
  var site = s.getAttribute("data-site") || location.hostname;
  var img = document.createElement("img");
  img.alt = "visitor counter";
  img.src = new URL("counter.svg", s.src).href + "?site=" + encodeURIComponent(site);
  s.parentNode.insertBefore(img, s);
})();
`
