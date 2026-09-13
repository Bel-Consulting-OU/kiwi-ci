package executor

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// defaultMaxLine is the default cap applied to a single emitted line.
const defaultMaxLine = 1 << 20

// streamLines drains r completely and emits its lines. It NEVER stops
// consuming: if a line exceeds maxLine the first maxLine bytes are emitted
// (truncated at a rune boundary where possible) with a "[line truncated: N
// bytes]" marker, and draining continues until the newline, so a writer on the
// other end of the pipe can never block on a full pipe. The reader is always
// read to EOF even when the emit callback would be slow.
func streamLines(r io.Reader, maxLine int, emit func(string)) {
	if maxLine <= 0 {
		maxLine = defaultMaxLine
	}
	br := bufio.NewReaderSize(r, 64*1024)
	line := make([]byte, 0, 4096)
	var skipped int64
	var truncated bool

	emitLine := func() {
		if len(line) == 0 && !truncated {
			return
		}
		text := strings.TrimRight(string(line), "\r")
		if truncated {
			text += fmt.Sprintf("[line truncated: %d bytes]", skipped)
		}
		emit(text)
		line = line[:0]
		truncated = false
		skipped = 0
	}

	for {
		chunk, err := br.ReadSlice('\n')
		if err == nil {
			chunk = chunk[:len(chunk)-1] // drop the newline
		}
		if len(chunk) > 0 {
			if !truncated {
				room := maxLine - len(line)
				if room <= 0 {
					skipped += int64(len(chunk))
					truncated = true
				} else if room < len(chunk) {
					keep := chunk[:room]
					for len(keep) > 0 && !utf8.Valid(keep) {
						keep = keep[:len(keep)-1]
					}
					line = append(line, keep...)
					skipped += int64(len(chunk) - len(keep))
					truncated = true
				} else {
					line = append(line, chunk...)
				}
			} else {
				skipped += int64(len(chunk))
			}
		}
		switch err {
		case nil:
			emitLine()
		case bufio.ErrBufferFull:
			// The 64 KiB read buffer filled before a newline; keep draining.
		case io.EOF:
			emitLine()
			return
		default:
			// Read error: flush whatever was accumulated and stop.
			emitLine()
			return
		}
	}
}
