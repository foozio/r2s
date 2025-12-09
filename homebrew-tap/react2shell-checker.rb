class React2shellChecker < Formula
  include Language::Python::Virtualenv

  desc "React2Shell (CVE-2025-55182) Vulnerability Detector"
  homepage "https://github.com/foozio/r2s"
  url "https://github.com/foozio/r2s/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256" # Replace with actual SHA256
  license "MIT"

  depends_on "python@3.9"

  resource "requests" do
    url "https://files.pythonhosted.org/packages/9d/be/10918a2eac4ae9f02f6cfe6414b7a155ccd8f7f9d4380d62fd5b955065c3c3b/requests-2.31.0.tar.gz"
    sha256 "942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1a19"
  end

  resource "packaging" do
    url "https://files.pythonhosted.org/packages/49/df/1fceb2f8900f8639e278b056419d29f4f679ecdc13d01cdcbfbcd57faec6a7/Packaging-21.3.tar.gz"
    sha256 "dd47c42927d89ab911e606518907cc2d3a1f38bbd026385970643f9c5b8ecfeb478"
  end

  resource "pyyaml" do
    url "https://files.pythonhosted.org/packages/36/2b/61d51a2c4f25ef062ae3f74576b01638bebad5e045f747ff12643df63844bfb/PyYAML-6.0.tar.gz"
    sha256 "68fb519c14306fec9720a2a5b45bc9f0c8d1b9c72adf45c37baedfcd949c35a2d99"
  end

  def install
    virtualenv_install_with_resources

    # Install the main script
    bin.install "react2shell_checker_unified.py" => "react2shell-checker"

    # Install default config
    prefix.install "react2shell.yaml"

    # Create symlink for config
    ln_s prefix/"react2shell.yaml", etc/"react2shell.yaml"
  end

  test do
    # Basic functionality test
    system "#{bin}/react2shell-checker", "--help"

    # Test with a simple directory
    (testpath/"test-project").mkdir
    (testpath/"test-project/package.json").write <<~EOS
      {
        "name": "test",
        "dependencies": {
          "react": "18.2.0"
        }
      }
    EOS

    output = shell_output("#{bin}/react2shell-checker --path #{testpath}/test-project --json")
    assert_match '"vulnerabilities_found": false', output
  end
end