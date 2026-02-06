"""
Fix icon generation to properly create multi-size ICO file.
"""
from PIL import Image
import os

def create_multi_size_ico():
    """Create proper Windows ICO with all sizes."""
    # Load the source PNG
    png_path = os.path.join('crash_analyzer', 'icon.png')
    source = Image.open(png_path)
    
    # Ensure RGBA mode
    if source.mode != 'RGBA':
        source = source.convert('RGBA')
    
    # Create all required sizes
    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    images = []
    
    for size in sizes:
        resized = source.resize(size, Image.Resampling.LANCZOS)
        images.append(resized)
    
    # Save ICO with all sizes
    ico_path = os.path.join('crash_analyzer', 'icon.ico')
    images[0].save(ico_path, format='ICO', sizes=sizes)
    print(f"✓ Created: {ico_path}")
    
    # Also save to root
    root_ico_path = 'icon.ico'
    images[0].save(root_ico_path, format='ICO', sizes=sizes)
    print(f"✓ Created: {root_ico_path}")
    
    # Verify
    test_ico = Image.open(ico_path)
    print(f"\nVerification:")
    print(f"  Default size: {test_ico.size}")
    print(f"  File size: {os.path.getsize(ico_path)} bytes")

if __name__ == "__main__":
    create_multi_size_ico()
