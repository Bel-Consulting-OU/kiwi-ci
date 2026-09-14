# Homebrew formula for Kiwi CI (bottle-less).
#
# This formula downloads the prebuilt darwin binary from the GitHub release
# matching `version` and installs it to bin. `brew install` verifies the
# SHA256 recorded below and fails on an unreplaced placeholder, which is
# intentional: never ship a formula without a verified digest.
#
# Release tooling refreshes this file: `scripts/release.sh vX.Y.Z
# --update-formula` replaces both PLACEHOLDER hashes with the digests of the
# freshly built kiwi-darwin-arm64 / kiwi-darwin-amd64 binaries (the script
# also prints both hashes next to the SHA256SUMS it produces). Bump `version`
# at the same time so it matches the tag. To publish through a tap instead,
# copy this file into the tap and run the same release step.
class Kiwi < Formula
  desc "Single-binary CI/CD engine: CLI, control plane, and runner"
  homepage "https://github.com/Bel-Consulting-OU/kiwi-ci"
  license "Apache-2.0"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Bel-Consulting-OU/kiwi-ci/releases/download/v#{version}/kiwi-darwin-arm64"
      sha256 "PLACEHOLDER-DARWIN-ARM64-SHA256"
    else
      url "https://github.com/Bel-Consulting-OU/kiwi-ci/releases/download/v#{version}/kiwi-darwin-amd64"
      sha256 "PLACEHOLDER-DARWIN-AMD64-SHA256"
    end
  end

  def install
    bin.install Dir["kiwi-darwin-*"].first => "kiwi"
  end

  test do
    assert_match "kiwi", shell_output("#{bin}/kiwi version")
  end
end
