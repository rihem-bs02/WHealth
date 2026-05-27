import glob
import json
import re
from pathlib import Path

def main():
    recovered_lines = {}
    
    # Pattern to match "123: code line" or "123:code line"
    line_pattern = re.compile(r"^(\d+):\s?(.*)$")
    
    transcripts = glob.glob("C:/Users/rihem/.gemini/antigravity/brain/*/.system_generated/logs/transcript.jsonl")
    print(f"Found {len(transcripts)} transcripts.")
    
    for t_path in transcripts:
        print(f"Processing {t_path}...")
        try:
            with open(t_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        step = json.loads(line)
                    except Exception:
                        continue
                    
                    # We are looking for VIEW_FILE step type or tool outputs that contain desktop_app.py contents
                    content = step.get("content")
                    if not content or "desktop_app.py" not in content:
                        continue
                    
                    # Parse the lines from this view content
                    lines = content.splitlines()
                    count = 0
                    for l in lines:
                        match = line_pattern.match(l.strip())
                        if match:
                            line_num = int(match.group(1))
                            line_content = match.group(2)
                            # Store the line content. If we already recovered it, they should be the same.
                            recovered_lines[line_num] = line_content
                            count += 1
                    if count > 0:
                        print(f"  Recovered {count} lines from this step.")
        except Exception as e:
            print(f"Error reading {t_path}: {e}")
            
    print(f"Total unique lines recovered: {len(recovered_lines)}")
    if not recovered_lines:
        print("No lines recovered!")
        return
        
    max_line = max(recovered_lines.keys())
    print(f"Max line number: {max_line}")
    
    # Let's write out the reconstructed file
    reconstructed_path = Path("desktop_app_recovered.py")
    with open(reconstructed_path, "w", encoding="utf-8") as out:
        for i in range(1, max_line + 1):
            if i in recovered_lines:
                out.write(recovered_lines[i] + "\n")
            else:
                out.write(f"# MISSING LINE {i}\n")
                
    print(f"Reconstructed file written to {reconstructed_path.absolute()}")

if __name__ == "__main__":
    main()
