package tcpport

import (
	"io"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// WildcardMatch checks if str matches pattern with * and ? wildcards.
func WildcardMatch(str, pattern string) bool {
	n := len(pattern)
	i, j := 0, 0
	asterisk, match := -1, 0
	for i < len(str) {
		if j < n && pattern[j] == '*' {
			match = i
			asterisk = j
			j++
		} else if j < n && (str[i] == pattern[j] || pattern[j] == '?') {
			i++
			j++
		} else if asterisk >= 0 {
			match++
			i = match
			j = asterisk + 1
		} else {
			return false
		}
	}
	for j < n && pattern[j] == '*' {
		j++
	}
	return j == n
}

// DiscardAll reads and discards all data from reader, returning bytes discarded.
func DiscardAll(r io.Reader) int {
	buf := make([]byte, 32768)
	n := 0
	for {
		nn, err := r.Read(buf)
		n += nn
		if err != nil {
			break
		}
	}
	return n
}

// ReadToStringWithCharset reads reader content into a string with the given charset.
func ReadToStringWithCharset(reader io.Reader, charset string) (string, error) {
	charset = strings.ToUpper(charset)
	if charset == "UTF-8" || charset == "UTF8" {
		data, err := io.ReadAll(reader)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	if charset == "GBK" || charset == "GB2312" {
		charset = "GB18030"
	}
	encoder, err := htmlindex.Get(charset)
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(transform.NewReader(reader, encoder.NewDecoder()))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

var _ encoding.Encoding
