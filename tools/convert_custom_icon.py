"""
Convert a custom PNG icon to the required formats.
Place your source icon as 'custom_icon.png' in this directory and run this script.
"""
from PIL import Image
import os
import sys

def convert_icon(source_path='custom_icon.png'):
    """Convert source PNG to optimized formats."""
    if not os.path.exists(source_path):
        print(f"❌ Error: '{source_path}' not found!")
        print("\nPlease save your icon image as 'custom_icon.png' in this directory.")
        sys.exit(1)
    
    print(f"Loading: {source_path}")
    source = Image.open(source_path)
    
    # Ensure RGBA mode with transparency
    if source.mode != 'RGBA':
        source = source.convert('RGBA')
    
    print(f"Source size: {source.size}")
    
    # Create 256x256 PNG for main icon
    icon_256 = source.resize((256, 256), Image.Resampling.LANCZOS)
    
    # Save to crash_analyzer folder
    icon_dir = 'crash_analyzer'
    os.makedirs(icon_dir, exist_ok=True)
    
    png_path = os.path.join(icon_dir, 'icon.png')
    icon_256.save(png_path, 'PNG', optimize=True)
    print(f"✓ Created: {png_path}")
    
    # Also save to root
    root_png_path = 'icon.png'
    icon_256.save(root_png_path, 'PNG', optimize=True)
    print(f"✓ Created: {root_png_path}")
    
    # Create multi-size ICO for Windows
    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    
    ico_path = os.path.join(icon_dir, 'icon.ico')
    icon_256.save(ico_path, format='ICO', sizes=sizes)
    print(f"✓ Created: {ico_path} (sizes: 16-256)")
    
    root_ico_path = 'icon.ico'
    icon_256.save(root_ico_path, format='ICO', sizes=sizes)
    print(f"✓ Created: {root_ico_path}")
    
    print("\n✓ Icon conversion complete!")
    print("The FiveM crash icon is now ready to use.")

if __name__ == "__main__":
    convert_icon()
