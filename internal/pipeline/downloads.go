package pipeline

import "strings"

// ArtifactInputsPartition splits declared downloads into setup-time
// restores (empty `if`, success() or always()) and failure()-gated
// restores. Shared by the local executor and the distributed runner so
// both paths honor the same condition contract.
func ArtifactInputsPartition(inputs []ArtifactInput) (setup, onFailure []ArtifactInput) {
	for _, d := range inputs {
		switch strings.TrimSpace(d.If) {
		case "", "success()", "always()":
			setup = append(setup, d)
		default:
			onFailure = append(onFailure, d)
		}
	}
	return setup, onFailure
}
