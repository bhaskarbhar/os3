import xml.etree.ElementTree as ET
from pathlib import Path

def parse_pom_xml(file_path: str) -> list[dict]:
    """Parse a Maven pom.xml file to extract dependencies."""
    path = Path(file_path)
    if not path.exists():
        return []
        
    try:
        # We need to handle namespaces in pom.xml
        tree = ET.parse(path)
        root = tree.getroot()
        
        # Extract namespace if present
        ns = ""
        if "}" in root.tag:
            ns = root.tag.split("}")[0] + "}"
            
        dependencies = []
        
        # Look for dependencies in <dependencies> section
        deps_node = root.find(f".//{ns}dependencies")
        if deps_node is not None:
            for dep in deps_node.findall(f"{ns}dependency"):
                gid = dep.find(f"{ns}groupId")
                aid = dep.find(f"{ns}artifactId")
                ver = dep.find(f"{ns}version")
                
                if gid is not None and aid is not None:
                    # Resolve version if it's a property (simple resolution only)
                    version_text = ver.text if ver is not None else "LATEST"
                    if version_text.startswith("${") and version_text.endswith("}"):
                        prop_name = version_text[2:-1]
                        prop_node = root.find(f".//{ns}properties/{ns}{prop_name}")
                        if prop_node is not None:
                            version_text = prop_node.text
                    
                    dependencies.append({
                        "name": f"{gid.text}:{aid.text}",
                        "version": version_text,
                        "ecosystem": "maven"
                    })
        
        return dependencies
    except Exception:
        return []
