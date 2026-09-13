package logging

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/kiwici/kiwi/internal/secrets"
)

type Sink interface{ WriteLine(job, step, line string) }

type Console struct {
	Mu     sync.Mutex
	Masker *secrets.Masker
	Writer io.Writer
}

func (c *Console) WriteLine(job, step, line string) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if c.Writer == nil {
		return
	}
	if c.Masker != nil {
		line = c.Masker.Mask(line)
	}
	fmt.Fprintf(c.Writer, "[%s] [%s/%s] %s\n", time.Now().Format("15:04:05"), job, step, line)
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
