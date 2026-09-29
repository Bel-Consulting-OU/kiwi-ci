package forge

import (
	"errors"
	"net/http"
)

// failingTransportClient returns a client whose transport always fails, for
// deterministic "transport error must fail" assertions.
//
// The historical pattern (create an httptest server, Close it, then request
// its URL) is flaky: ephemeral ports are reused, and another test binary
// running in parallel can bind the same port before the request, making it
// succeed. This client cannot be re-bound by anyone.
func failingTransportClient() *http.Client {
	return &http.Client{Transport: failTransport{}}
}

// failingBaseURL is an address no server can be listening on for these
// tests, paired with failingTransportClient.
const failingBaseURL = "http://127.0.0.1:1"

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("injected transport failure")
}
