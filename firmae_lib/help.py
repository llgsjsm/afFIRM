import os

def _load_help_md(firmae_home: str) -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmae_help.md")
    try:
        with open(path, "r", encoding="utf-8") as f:
            txt = f.read()
        return txt.replace("{FIRMAE_HOME}", firmae_home)
    except Exception as e:
        return f"[help missing] Could not read {path}: {e}"