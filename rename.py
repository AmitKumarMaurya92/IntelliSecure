import os

def replace_in_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        if 'IntelliSecure' in content:
            content = content.replace('IntelliSecure', 'IntelliSecure')
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Updated {filepath}")
    except Exception as e:
        # Ignore binary files or files with encoding issues
        pass

def main():
    root_dir = r"d:\IntelliSecure"
    exclude_dirs = {'.git', '__pycache__', 'venv', 'node_modules', '.gemini'}
    
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for filename in filenames:
            if filename.endswith(('.sqlite3', '.db', '.pyc', '.png', '.jpg', '.ico', '.pdf', '.pptx')):
                continue
            filepath = os.path.join(dirpath, filename)
            replace_in_file(filepath)

if __name__ == '__main__':
    main()
