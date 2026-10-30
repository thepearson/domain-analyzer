package analyzer

import (
	"bytes"
	"encoding/binary"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/webp"
)

var (
	linkTagRegex = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	relAttrRegex = regexp.MustCompile(`(?is)\brel\s*=\s*["']?([^"'\s>]+)["']?`)
	hrefRegex    = regexp.MustCompile(`(?is)\bhref\s*=\s*["']([^"']+)["']`)
)

// FetchFavicon attempts to locate, download, and normalize a website's favicon into PNG/SVG/image bytes.
func FetchFavicon(pageURL string, htmlBody []byte, client *http.Client) []byte {
	if client == nil {
		return nil
	}
	parsedBase, err := url.Parse(pageURL)
	if err != nil || parsedBase.Host == "" {
		return nil
	}

	var candidates []string
	seen := make(map[string]bool)
	addCandidate := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || strings.HasPrefix(u, "data:") {
			return
		}
		resolved, err := parsedBase.Parse(u)
		if err != nil || (resolved.Scheme != "http" && resolved.Scheme != "https") {
			return
		}
		str := resolved.String()
		if !seen[str] {
			seen[str] = true
			candidates = append(candidates, str)
		}
	}

	// 1. Extract <link rel="icon|shortcut icon|apple-touch-icon" href="..."> from HTML
	if len(htmlBody) > 0 {
		for _, tag := range linkTagRegex.FindAllString(string(htmlBody), 50) {
			lowerTag := strings.ToLower(tag)
			if !strings.Contains(lowerTag, "icon") {
				continue
			}
			relMatch := relAttrRegex.FindStringSubmatch(tag)
			if len(relMatch) < 2 && !strings.Contains(lowerTag, "shortcut icon") && !strings.Contains(lowerTag, "apple-touch-icon") {
				continue
			}
			hrefMatch := hrefRegex.FindStringSubmatch(tag)
			if len(hrefMatch) >= 2 {
				addCandidate(hrefMatch[1])
			}
		}
	}

	// 2. Standard root fallbacks
	origin := parsedBase.Scheme + "://" + parsedBase.Host
	addCandidate(origin + "/favicon.ico")
	addCandidate(origin + "/favicon.png")

	for _, candidate := range candidates {
		if data := downloadAndNormalizeFavicon(candidate, client); len(data) > 0 {
			return data
		}
	}

	return nil
}

func downloadAndNormalizeFavicon(iconURL string, client *http.Client) []byte {
	req, err := http.NewRequest("GET", iconURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", wafUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil || len(raw) == 0 {
		return nil
	}

	return NormalizeFaviconBytes(raw)
}

// NormalizeFaviconBytes converts raw favicon bytes (including .ico containers) into a format
// directly decodable by MyGo's ui.DecodeImage or ui.ParseSVG (PNG, JPEG, GIF, WebP, BMP, or SVG).
func NormalizeFaviconBytes(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 4 {
		return nil
	}

	// Check if it is an SVG
	if bytes.HasPrefix(trimmed, []byte("<svg")) || (bytes.HasPrefix(trimmed, []byte("<?xml")) && bytes.Contains(trimmed, []byte("<svg"))) {
		return trimmed
	}

	// Check if it is an ICO container (00 00 01 00)
	if len(raw) >= 6 && raw[0] == 0x00 && raw[1] == 0x00 && raw[2] == 0x01 && raw[3] == 0x00 {
		if converted := extractICOToPNG(raw); len(converted) > 0 {
			return converted
		}
	}

	// Check if standard Go image decoders (PNG, JPEG, GIF, BMP, WebP) can decode it
	if img, _, err := image.Decode(bytes.NewReader(raw)); err == nil && img != nil {
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err == nil {
			return buf.Bytes()
		}
		return raw
	}

	return nil
}

// extractICOToPNG extracts the best image frame from a Windows .ico file and returns PNG bytes.
func extractICOToPNG(ico []byte) []byte {
	if len(ico) < 6 {
		return nil
	}
	count := int(binary.LittleEndian.Uint16(ico[4:6]))
	if count <= 0 || count > 64 || len(ico) < 6+count*16 {
		return nil
	}

	bestIdx := -1
	bestScore := -1
	var bestBytes []byte

	for i := 0; i < count; i++ {
		entryOffset := 6 + i*16
		w := int(ico[entryOffset])
		if w == 0 {
			w = 256
		}
		h := int(ico[entryOffset+1])
		if h == 0 {
			h = 256
		}
		bpp := int(binary.LittleEndian.Uint16(ico[entryOffset+6 : entryOffset+8]))
		size := int(binary.LittleEndian.Uint32(ico[entryOffset+8 : entryOffset+12]))
		offset := int(binary.LittleEndian.Uint32(ico[entryOffset+12 : entryOffset+16]))

		if size <= 0 || offset < 0 || offset+size > len(ico) {
			continue
		}
		frame := ico[offset : offset+size]

		// Prefer embedded PNG frames or higher resolution / bit-depth frames
		isPNG := len(frame) > 8 && bytes.Equal(frame[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
		score := w*h*10 + bpp
		if isPNG {
			score += 1_000_000
		}
		if score > bestScore {
			bestScore = score
			bestIdx = i
			bestBytes = frame
		}
	}

	if bestIdx < 0 || len(bestBytes) == 0 {
		return nil
	}

	// If the frame is already an embedded PNG, return it directly
	if len(bestBytes) > 8 && bytes.Equal(bestBytes[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}) {
		return bestBytes
	}

	// Otherwise, try decoding 32-bit/24-bit DIB inside ICO
	if img := decodeICODIB(bestBytes); img != nil {
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err == nil {
			return buf.Bytes()
		}
	}

	return nil
}

// decodeICODIB decodes an uncompressed 32-bit BGRA or 24-bit BGR BITMAPINFOHEADER inside an .ico entry.
func decodeICODIB(dib []byte) image.Image {
	if len(dib) < 40 {
		return nil
	}
	headerSize := binary.LittleEndian.Uint32(dib[0:4])
	if headerSize != 40 {
		return nil
	}
	width := int(int32(binary.LittleEndian.Uint32(dib[4:8])))
	heightCombined := int(int32(binary.LittleEndian.Uint32(dib[8:12])))
	height := heightCombined / 2 // ICO DIB height includes XOR + AND masks
	bpp := binary.LittleEndian.Uint16(dib[14:16])
	compression := binary.LittleEndian.Uint32(dib[16:20])

	if width <= 0 || width > 512 || height <= 0 || height > 512 || compression != 0 {
		return nil
	}
	if bpp != 32 && bpp != 24 {
		return nil
	}

	rowStride := ((width*int(bpp) + 31) / 32) * 4
	pixelDataLen := rowStride * height
	if int(headerSize)+pixelDataLen > len(dib) {
		return nil
	}

	pixels := dib[headerSize : int(headerSize)+pixelDataLen]
	img := image.NewNRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		// DIB rows are stored bottom-up
		srcRow := pixels[(height-1-y)*rowStride : (height-y)*rowStride]
		dstY := y * img.Stride
		for x := 0; x < width; x++ {
			if bpp == 32 {
				b := srcRow[x*4+0]
				g := srcRow[x*4+1]
				r := srcRow[x*4+2]
				a := srcRow[x*4+3]
				img.Pix[dstY+x*4+0] = r
				img.Pix[dstY+x*4+1] = g
				img.Pix[dstY+x*4+2] = b
				img.Pix[dstY+x*4+3] = a
			} else {
				b := srcRow[x*3+0]
				g := srcRow[x*3+1]
				r := srcRow[x*3+2]
				img.Pix[dstY+x*4+0] = r
				img.Pix[dstY+x*4+1] = g
				img.Pix[dstY+x*4+2] = b
				img.Pix[dstY+x*4+3] = 255
			}
		}
	}
	return img
}

