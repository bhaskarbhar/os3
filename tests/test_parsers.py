import pytest
import tempfile
from pathlib import Path
from os3.scan import parse_pip_requirements, scan_file

def test_parse_pip_requirements():
    """Test parsing a requirements.txt file."""
    content = "requests==2.31.0\nflask>=2.0.0\ndjango\n"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
        
    try:
        deps = parse_pip_requirements(tmp_path)
        assert len(deps) == 3
        assert deps[0]["name"] == "requests"
        assert deps[0]["version"] == "2.31.0"
        assert deps[1]["name"] == "flask"
        assert deps[1]["version"] is None # Specifier >= doesn't set exact version in our parser
        assert deps[2]["name"] == "django"
    finally:
        Path(tmp_path).unlink()

def test_scan_file_dispatch(mocker):
    """Test that scan_file dispatches to the correct parser based on filename."""
    # Mock the specific parsers
    mock_pip = mocker.patch("os3.scan.parse_pip_requirements", return_value=[])
    mock_npm = mocker.patch("os3.npm_parser.parse_npm_files", return_value=[])
    mock_maven = mocker.patch("os3.maven_parser.parse_pom_xml", return_value=[])
    
    # Test requirements.txt
    scan_file("requirements.txt")
    mock_pip.assert_called_once()
    
    # Test package.json
    # Note: npm_parser takes a directory
    with tempfile.TemporaryDirectory() as tmp_dir:
        pkg_json = Path(tmp_dir) / "package.json"
        pkg_json.write_text("{}")
        scan_file(str(pkg_json))
        mock_npm.assert_called_once()
    
    # Test pom.xml
    scan_file("pom.xml")
    mock_maven.assert_called_once()
