module github.com/Bel-Consulting-OU/kiwi-ci/tools

go 1.27.2

require honnef.co/go/tools v0.8.1

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	// staticcheck v0.8.1 pins an x/tools that cannot decode Go 1.27.2 compiler
	// export data ("export data version 5 is greater than maximum supported
	// version 4"). This explicit override tracks the upstream fix until a
	// staticcheck release carries it; see scripts/../Makefile staticcheck-all.
	golang.org/x/tools v0.51.1-0.20261009172652-1e27b6e00285 // indirect
)
