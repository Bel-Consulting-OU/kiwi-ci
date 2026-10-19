package logging

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

type Sink interface{ WriteLine(job, step, line string) }

type Console struct {
	Mu     sync.Mutex
	Masker *secrets.Masker
	Writer io.Writer
	// writeErr records the first writer failure (e.g. EPIPE when the
	// consumer closed the pipe). Callers can inspect it to explain a
	// silent console instead of assuming the step produced no output.
	writeErr error
}

// WriteErr returns the first console write failure, if any.
func (c *Console) WriteErr() error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	return c.writeErr
}

func (c *Console) WriteLine(job, step, line string) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if c.Writer == nil {
		return
	}
	if c.Masker != nil {
		line = c.Masker.MaskMulti(line)
	}
	// fmt.Fprintf ignores the error, which is how `kiwi run | head` used to
	// swallow a whole step's output when the pipe closed under us. Record
	// the write; a broken pipe stops further writes but never fakes success.
	if _, err := fmt.Fprintf(c.Writer, "[%s] [%s/%s] %s\n", time.Now().Format("15:04:05"), job, step, line); err != nil {
		c.writeErr = err
	}
}

type Func func(job, step, line string)

func (f Func) WriteLine(j, s, l string) { f(j, s, l) }

type Multi []Sink

func (m Multi) WriteLine(j, s, l string) {
	for _, x := range m {
		if x != nil {
			x.WriteLine(j, s, l)
		}
	}
}
