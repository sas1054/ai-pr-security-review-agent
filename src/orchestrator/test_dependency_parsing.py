"""Per-ecosystem coverage for dependency-control manifest parsing."""

import pytest

from scanner import _packages_from_file, run_typed_control_scan


def _names(path, content):
    return {name for name, _ in _packages_from_file(path, content)}


def test_npm_package_json_covers_every_dependency_section():
    content = """
    {
      "dependencies": {"web3": "^4.0.0"},
      "devDependencies": {"jest": "^29.0.0"},
      "peerDependencies": {"react": "^18.0.0"},
      "optionalDependencies": {"fsevents": "^2.3.0"}
    }
    """
    assert _names("package.json", content) == {"web3", "jest", "react", "fsevents"}


def test_npm_lock_file_reports_transitive_packages():
    content = """
    {
      "packages": {
        "": {"name": "payments"},
        "node_modules/bitcoinjs-lib": {"version": "6.1.0"},
        "node_modules/@scope/crypto-util": {"version": "1.0.0"}
      }
    }
    """
    assert {"bitcoinjs-lib", "@scope/crypto-util", "payments"} <= _names("package-lock.json", content)


def test_pyproject_reads_pep621_and_poetry_sections():
    content = """
[project]
dependencies = ["web3>=6.0.0", "requests[socks]==2.32.0"]

[tool.poetry.dependencies]
python = "^3.11"
eth-account = "0.11.0"

[tool.poetry.dev-dependencies]
pytest = "^8.0.0"
"""
    names = _names("pyproject.toml", content)
    assert {"web3", "requests", "eth-account", "pytest"} <= names
    assert "python" not in names


def test_poetry_lock_reports_resolved_packages():
    content = """
[[package]]
name = "web3"
version = "6.0.0"

[[package]]
name = "requests"
version = "2.32.0"
"""
    assert _names("poetry.lock", content) == {"web3", "requests"}


def test_requirements_file_keeps_real_line_numbers_and_skips_noise():
    content = "# crypto libraries\nrequests==2.32.0\n\n-r base.txt\nweb3==6.0.0  # blockchain\n"
    assert _packages_from_file("requirements.txt", content) == [("requests", 2), ("web3", 5)]


def test_nuget_project_and_lock_files_are_supported():
    csproj = """
    <Project>
      <ItemGroup>
        <PackageReference Include="Nethereum.Web3" Version="4.19.0" />
        <PackageReference Update="Serilog" Version="3.1.1" />
      </ItemGroup>
    </Project>
    """
    lock_file = """
    {"dependencies": {"net8.0": {"Nethereum.Web3": {"resolved": "4.19.0"}}}}
    """
    assert _names("src/Payments.csproj", csproj) == {"Nethereum.Web3", "Serilog"}
    assert _names("packages.lock.json", lock_file) == {"Nethereum.Web3"}


def test_maven_pom_reports_group_and_artifact():
    content = """
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <dependencies>
        <dependency>
          <groupId>org.web3j</groupId>
          <artifactId>core</artifactId>
        </dependency>
      </dependencies>
    </project>
    """
    assert _names("pom.xml", content) == {"org.web3j:core"}


def test_gradle_build_file_keeps_line_numbers():
    content = 'plugins { id "java" }\ndependencies {\n  implementation "org.web3j:core:4.9.8"\n}\n'
    assert _packages_from_file("build.gradle.kts", content) == [("org.web3j:core", 3)]


def test_go_modules_and_sums_keep_line_numbers():
    go_mod = "module payments\n\ngo 1.22\n\nrequire github.com/ethereum/go-ethereum v1.13.0\n"
    assert _packages_from_file("go.mod", go_mod) == [("github.com/ethereum/go-ethereum", 5)]
    go_sum = "github.com/ethereum/go-ethereum v1.13.0 h1:abc=\n"
    assert _packages_from_file("go.sum", go_sum) == [("github.com/ethereum/go-ethereum", 1)]


@pytest.mark.parametrize(
    "path, content",
    [
        ("package.json", "{ not json"),
        ("pyproject.toml", "[project\ndependencies = "),
        ("pom.xml", "<project><dependencies>"),
    ],
)
def test_unparseable_manifest_degrades_quietly(path, content):
    assert _packages_from_file(path, content) == []


def test_unsupported_manifest_reports_nothing():
    assert _packages_from_file("Cargo.toml", '[dependencies]\nweb3 = "0.19"\n') == []


def test_dependency_control_matches_exact_names_and_prefixes_but_not_substrings():
    control = {
        "control_id": "crypto.prohibited-dependencies",
        "version": "1.0",
        "control_type": "dependency",
        "severity": "ERROR",
        "detector": {"packages": ["web3"], "package_prefixes": ["coinbase-"], "file_globs": ["*requirements*.txt"]},
    }
    files = {"requirements.txt": "web3==6.0.0\ncoinbase-advanced-py==1.0.0\nweb3modal-helper==1.0.0\nrequests==2.32.0\n"}

    findings = run_typed_control_scan(files, [control])

    assert [(finding.matched_value, finding.line) for finding in findings] == [
        ("web3", 1),
        ("coinbase-advanced-py", 2),
    ]


def test_dependency_control_normalizes_separator_and_case_differences():
    control = {
        "control_id": "crypto.prohibited-dependencies",
        "version": "1.0",
        "control_type": "dependency",
        "severity": "ERROR",
        "detector": {"packages": ["Eth_Account"], "file_globs": ["*requirements*.txt"]},
    }

    findings = run_typed_control_scan({"requirements.txt": "eth-account==0.11.0\n"}, [control])

    assert len(findings) == 1
    assert findings[0].matched_value == "eth-account"
