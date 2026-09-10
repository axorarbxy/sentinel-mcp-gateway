"""
Generate simple shield icons for the Chrome extension
"""

from PIL import Image, ImageDraw
import os

def create_shield_icon(size):
    """Create a simple shield icon with Sentinel-MCP colors"""
    # Create RGBA image
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Colors
    primary = (66, 165, 245, 255)  # #42a5f5 - blue
    darker = (30, 136, 229, 255)   # #1e88e5 - darker blue
    accent = (144, 202, 249, 255)  # #90caf9 - light blue
    white = (255, 255, 255, 255)

    # Draw shield shape (approximated with polygon)
    padding = size * 0.1
    top = padding
    bottom = size - padding
    left = padding
    right = size - padding
    mid_x = size / 2
    mid_y = size * 0.65

    shield_points = [
        (left, top + size * 0.1),
        (mid_x, top),
        (right, top + size * 0.1),
        (right, mid_y),
        (mid_x, bottom),
        (left, mid_y),
    ]

    # Fill shield
    draw.polygon(shield_points, fill=primary, outline=darker)

    # Draw inner highlight
    inner_padding = size * 0.15
    inner_points = [
        (left + inner_padding, top + size * 0.15),
        (mid_x, top + inner_padding),
        (right - inner_padding, top + size * 0.15),
        (right - inner_padding, mid_y),
        (mid_x, bottom - inner_padding),
        (left + inner_padding, mid_y),
    ]
    draw.polygon(inner_points, fill=darker)

    # Draw a checkmark
    if size >= 48:
        check_size = size * 0.15
        check_points = [
            (mid_x - check_size * 0.6, mid_y - check_size * 0.1),
            (mid_x - check_size * 0.15, mid_y + check_size * 0.35),
            (mid_x + check_size * 0.7, mid_y - check_size * 0.5),
        ]
        line_width = max(2, int(size * 0.08))
        draw.line(check_points, fill=white, width=line_width, joint='curve')

    # Save
    filename = f'icons/icon{size}.png'
    os.makedirs('icons', exist_ok=True)
    # Use absolute path based on script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    icons_dir = os.path.join(script_dir, 'icons')
    os.makedirs(icons_dir, exist_ok=True)
    filename = os.path.join(icons_dir, f'icon{size}.png')
    img.save(filename, 'PNG')
    print(f'✅ Created {filename}')

if __name__ == '__main__':
    print('🎨 Generating Sentinel-MCP icons...\n')
    for size in [16, 48, 128]:
        create_shield_icon(size)
    print('\n✅ All icons generated in icons/ folder')