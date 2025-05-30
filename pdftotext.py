import PyPDF2
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

def extract_text_from_pdf(pdf_path):
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return text

def write_text_to_pdf(text, output_pdf_path):
    c = canvas.Canvas(output_pdf_path, pagesize=letter)
    width, height = letter
    lines = text.split('\n')
    y = height - 40
    for line in lines:
        c.drawString(40, y, line)
        y -= 15
        if y < 40:
            c.showPage()
            y = height - 40
    c.save()

def open_pdf():
    file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
    if file_path:
        text = extract_text_from_pdf(file_path)
        text_area.delete(1.0, tk.END)
        text_area.insert(tk.END, text)

def save_pdf():
    file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
    if file_path:
        text = text_area.get(1.0, tk.END)
        write_text_to_pdf(text, file_path)
        messagebox.showinfo("Saved", "PDF saved successfully.")

root = tk.Tk()
root.title("PDF Editor")
root.geometry("800x600")  # Set window size (width x height)

frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

open_btn = tk.Button(frame, text="Open PDF", command=open_pdf)
open_btn.pack(side=tk.LEFT, padx=5, pady=5)

save_btn = tk.Button(frame, text="Save PDF", command=save_pdf)
save_btn.pack(side=tk.LEFT, padx=5, pady=5)

text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

root.mainloop()
