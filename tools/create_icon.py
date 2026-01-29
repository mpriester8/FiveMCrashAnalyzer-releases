"""
Generate a professional icon for the FiveM Crash Analyzer.
Run this script to create icon.png in the crash_analyzer folder.
"""
from PySide6 import QtGui, QtCore
from PySide6.QtWidgets import QApplication
import sys
import os

def create_crash_analyzer_icon(size=256):
    """Create a professional crash analyzer icon."""
    pixmap = QtGui.QPixmap(size, size)
    pixmap.fill(QtCore.Qt.transparent)
    
    painter = QtGui.QPainter(pixmap)
    painter.setRenderHint(QtGui.QPainter.Antialiasing)
    painter.setRenderHint(QtGui.QPainter.SmoothPixmapTransform)
    
    center = size // 2
    
    # Draw outer glow effect
    for i in range(5, 0, -1):
        opacity = 0.1 * (6 - i)
        painter.setOpacity(opacity)
        painter.setBrush(QtGui.QColor(220, 53, 69))
        painter.setPen(QtCore.Qt.NoPen)
        radius = int(center * 0.85) + i * 3
        painter.drawEllipse(center - radius, center - radius, radius * 2, radius * 2)
    
    painter.setOpacity(1.0)
    
    # Draw main background circle with gradient
    gradient = QtGui.QRadialGradient(center, center, center * 0.85)
    gradient.setColorAt(0, QtGui.QColor(230, 60, 75))   # Bright red
    gradient.setColorAt(0.7, QtGui.QColor(200, 45, 60))  # Medium red
    gradient.setColorAt(1, QtGui.QColor(160, 30, 45))    # Dark red
    
    painter.setBrush(gradient)
    painter.setPen(QtGui.QPen(QtGui.QColor(120, 20, 30), size // 40))
    radius = int(center * 0.85)
    painter.drawEllipse(center - radius, center - radius, radius * 2, radius * 2)
    
    # Draw inner circle for depth
    inner_gradient = QtGui.QRadialGradient(center, center - size * 0.1, center * 0.6)
    inner_gradient.setColorAt(0, QtGui.QColor(255, 100, 110, 100))
    inner_gradient.setColorAt(1, QtCore.Qt.transparent)
    painter.setBrush(inner_gradient)
    painter.setPen(QtCore.Qt.NoPen)
    inner_radius = int(center * 0.7)
    painter.drawEllipse(center - inner_radius, center - inner_radius, inner_radius * 2, inner_radius * 2)
    
    # Draw crash/bug symbol - modern exclamation mark with circuit lines
    painter.setPen(QtGui.QPen(QtCore.Qt.white, size // 16, QtCore.Qt.SolidLine, QtCore.Qt.RoundCap))
    
    # Main exclamation line
    exclaim_top = int(center - radius * 0.45)
    exclaim_bottom = int(center + radius * 0.15)
    painter.drawLine(center, exclaim_top, center, exclaim_bottom)
    
    # Exclamation dot
    dot_y = int(center + radius * 0.35)
    dot_size = size // 20
    painter.setBrush(QtCore.Qt.white)
    painter.setPen(QtCore.Qt.NoPen)
    painter.drawEllipse(center - dot_size // 2, dot_y - dot_size // 2, dot_size, dot_size)
    
    # Draw circuit/antenna lines (bug antennae)
    painter.setPen(QtGui.QPen(QtGui.QColor(255, 255, 255, 200), size // 32, QtCore.Qt.SolidLine, QtCore.Qt.RoundCap))
    
    # Left antenna
    left_x = int(center - radius * 0.35)
    left_y = int(center - radius * 0.3)
    painter.drawLine(left_x, left_y, int(center - radius * 0.55), int(center - radius * 0.6))
    painter.drawLine(int(center - radius * 0.55), int(center - radius * 0.6), 
                    int(center - radius * 0.65), int(center - radius * 0.55))
    
    # Right antenna
    right_x = int(center + radius * 0.35)
    right_y = int(center - radius * 0.3)
    painter.drawLine(right_x, right_y, int(center + radius * 0.55), int(center - radius * 0.6))
    painter.drawLine(int(center + radius * 0.55), int(center - radius * 0.6),
                    int(center + radius * 0.65), int(center - radius * 0.55))
    
    # Draw small circuit nodes on antennae
    node_size = size // 40
    painter.setBrush(QtGui.QColor(255, 200, 100))  # Gold accent
    painter.drawEllipse(int(center - radius * 0.55) - node_size // 2, 
                       int(center - radius * 0.6) - node_size // 2, 
                       node_size, node_size)
    painter.drawEllipse(int(center + radius * 0.55) - node_size // 2,
                       int(center - radius * 0.6) - node_size // 2,
                       node_size, node_size)
    
    # Add subtle "scan lines" effect
    painter.setOpacity(0.1)
    painter.setPen(QtGui.QPen(QtCore.Qt.white, 1))
    step = max(1, size // 20)  # Ensure step is at least 1
    for y in range(0, size, step):
        painter.drawLine(0, y, size, y)
    
    painter.end()
    
    return pixmap

def main():
    app = QApplication(sys.argv)
    
    # Create icon at multiple sizes
    sizes = [256, 128, 64, 48, 32, 16]
    
    print("Creating FiveM Crash Analyzer icon...")
    
    # Create main PNG icon (optimized size)
    main_icon = create_crash_analyzer_icon(256)  # Use 256x256 for better quality
    icon_dir = os.path.join(os.path.dirname(__file__), 'crash_analyzer')
    os.makedirs(icon_dir, exist_ok=True)
    
    png_path = os.path.join(icon_dir, 'icon.png')
    main_icon.save(png_path, 'PNG')
    print(f"✓ Created: {png_path}")
    
    # Also save to root directory
    root_png_path = os.path.join(os.path.dirname(__file__), 'icon.png')
    main_icon.save(root_png_path, 'PNG')
    print(f"✓ Created: {root_png_path}")
    
    # Create .ico file with multiple sizes (for Windows)
    try:
        from PIL import Image
        import io
        
        # Create proper multi-size ICO file with all necessary sizes
        ico_sizes = [256, 128, 64, 48, 32, 16]
        ico_images = []
        
        for size in ico_sizes:
            pixmap = create_crash_analyzer_icon(size)
            buffer = QtCore.QBuffer()
            buffer.open(QtCore.QIODevice.WriteOnly)
            pixmap.save(buffer, "PNG")
            buffer.close()
            
            pil_image = Image.open(io.BytesIO(buffer.data()))
            # Convert to RGBA for proper transparency
            if pil_image.mode != 'RGBA':
                pil_image = pil_image.convert('RGBA')
            ico_images.append(pil_image)
        
        # Save as ICO with all sizes embedded
        ico_path = os.path.join(icon_dir, 'icon.ico')
        ico_images[0].save(
            ico_path, 
            format='ICO', 
            sizes=[(s, s) for s in ico_sizes],
            append_images=ico_images[1:]
        )
        print(f"✓ Created: {ico_path} (sizes: {', '.join(map(str, ico_sizes))})")
        
        # Also save to root
        root_ico_path = os.path.join(os.path.dirname(__file__), 'icon.ico')
        ico_images[0].save(
            root_ico_path,
            format='ICO',
            sizes=[(s, s) for s in ico_sizes],
            append_images=ico_images[1:]
        )
        print(f"✓ Created: {root_ico_path}")
        
    except ImportError:
        print("⚠ Pillow not installed - ICO file creation skipped")
        print("  Install with: pip install Pillow")
        print("  The PNG icon will work fine on all platforms")
    
    print("\n✓ Icon creation complete!")
    print(f"\nThe application will now show a professional crash analyzer icon.")
    print(f"You can replace {png_path} with your own custom icon if desired.")

if __name__ == "__main__":
    main()
