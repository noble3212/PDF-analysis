import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

SUSPICIOUS_KEYWORDS = [
    b'/JavaScript', b'/JS', b'/Launch', b'/EmbeddedFile',
    b'/OpenAction', b'/AA', b'/RichMedia', b'/URI'
]

class PDFAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deep PDF Analyzer")
        self.create_widgets()

    def create_widgets(self):
        self.frame = tk.Frame(self.root)
        self.frame.pack(padx=10, pady=10)

        self.label = tk.Label(self.frame, text="Select a PDF file to analyze:")
        self.label.pack(anchor="w")

        self.select_btn = tk.Button(self.frame, text="Browse...", command=self.browse_file)
        self.select_btn.pack(anchor="w", pady=(5, 10))

        self.analyze_btn = tk.Button(self.frame, text="Analyze", command=self.analyze_selected_file, state="disabled")
        self.analyze_btn.pack(anchor="w")

        self.text_area = scrolledtext.ScrolledText(self.root, width=100, height=35, wrap=tk.WORD)
        self.text_area.pack(padx=10, pady=10)

        self.file_path = None

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if file_path:
            self.file_path = file_path
            self.label.config(text=f"Selected: {os.path.basename(file_path)}")
            self.analyze_btn.config(state="normal")

    def analyze_selected_file(self):
        if not self.file_path:
            messagebox.showerror("Error", "No file selected.")
            return
        self.text_area.delete(1.0, tk.END)
        try:
            output = self.analyze_pdf(self.file_path)
            self.text_area.insert(tk.END, output)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def analyze_pdf(self, file_path):
        output = []
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            output.append("=== PDF STRUCTURE & SECURITY ANALYSIS ===\n")
            output.append(f"File: {os.path.basename(file_path)}\n")
            output.append(f"File size: {len(data)} bytes\n\n")

            # Check header
            header_match = re.search(br'%PDF-(\d\.\d)', data)
            if header_match:
                version = header_match.group(1).decode()
                output.append(f"PDF version: {version}\n")
            else:
                output.append("PDF version: Unknown (header not found)\n")

            # Object count
            object_count = len(re.findall(br'\n\d+\s+\d+\s+obj', data))
            output.append(f"PDF objects detected: {object_count}\n")

            # Suspicious keyword analysis
            output.append("\n--- Suspicious Keyword Check ---\n")
            found_keywords = []
            for keyword in SUSPICIOUS_KEYWORDS:
                count = data.count(keyword)
                if count > 0:
                    found_keywords.append((keyword.decode('latin1'), count))
            if found_keywords:
                for kw, count in found_keywords:
                    output.append(f"Found {kw} ({count} times)\n")
            else:
                output.append("No suspicious keywords found.\n")

            # Trailer info
            trailer_match = re.search(br'trailer[\s]*<<[\s\S]*?>>', data)
            if trailer_match:
                output.append("\n--- Trailer ---\n")
                trailer = trailer_match.group().decode(errors='replace')
                output.append(trailer + "\n")
            else:
                output.append("\nTrailer section not found.\n")

            # JavaScript content snippet
            js_matches = re.findall(br'/JS\s*(\((.*?)\)|<([0-9A-Fa-f\s]+)>)', data)
            if js_matches:
                output.append("\n--- Embedded JavaScript ---\n")
                for match in js_matches:
                    script = match[1] or match[2]
                    try:
                        if match[2]:  # hex
                            script = bytes.fromhex(match[2].replace(" ", "")).decode("utf-8", errors="replace")
                        output.append(f"JavaScript found:\n{script[:300]}...\n")
                    except Exception:
                        output.append("Failed to decode JavaScript.\n")
            else:
                output.append("\nNo embedded JavaScript found.\n")

        except Exception as e:
            output.append(f"Error reading file: {e}\n")

        return ''.join(output)

def main():
    root = tk.Tk()
    app = PDFAnalyzerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
