package candidate

import "runtime"

// runtimeGOOS/GOARCH mirror the host the test process runs on.
var (
	runtimeGOOS   = runtime.GOOS
	runtimeGOARCH = runtime.GOARCH
)
