class Moco < Formula
  desc 'MCP Observation and Control Operator'
  homepage 'https://github.com/altescy/moco'
  head 'https://github.com/altescy/moco.git', branch: 'main'

  depends_on 'rust' => :build

  def install
    system 'cargo', 'install', *std_cargo_args(path: '.')
  end

  test do
    assert_match 'moco', shell_output("#{bin}/moco --help")
  end
end
