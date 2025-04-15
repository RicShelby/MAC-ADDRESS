
'''
Names:
CURSAT, Nica Mae
ESCABAS, Roy Ian
GANOY, Rubilee
MAGLINTE, Renie Boy
MULAAN, Ric Ann
'''

# Before running this, download first these 2 packages: (1) pycairo (2)mac-vendor-lookup

import re
import subprocess
import cairo
import math
from typing import Optional, Tuple
from mac_vendor_lookup import MacLookup, VendorNotFoundError


def draw_nfa_diagram(
        surface: cairo.Surface,
        mac: str,
        is_unicast: bool,
        is_global: bool,
        vendor: Optional[str]
) -> None:
    """Draw NFA diagram for MAC address with proper state transitions"""
    context = cairo.Context(surface)
    width, height = surface.get_width(), surface.get_height()

    # Set background
    context.set_source_rgb(1, 1, 1)
    context.paint()

    # Set colors
    state_color = (0.2, 0.4, 0.8)
    arrow_color = (0.3, 0.3, 0.3)
    text_color = (1, 1, 1)
    transition_color = (0.5, 0.2, 0.2)

    # Build transition list including colons
    transitions = []
    for i, octet in enumerate(mac.split(':')):
        transitions.extend(list(octet))
        if i < 5:
            transitions.append(':')

    num_states = len(transitions)

    # Calculate dynamic spacing based on surface width
    state_radius = 30
    min_spacing = 80
    max_spacing = 120
    available_width = width - 200  # for margins
    spacing = min(max_spacing, max(min_spacing, available_width // num_states))

    start_x = 100
    y = height // 2

    # Draw title and info
    context.set_source_rgb(0, 0, 0)
    context.select_font_face("Arial", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_BOLD)
    context.set_font_size(24)
    context.move_to(50, 40)
    context.show_text("MAC Address Finite Automaton")

    context.set_font_size(16)
    context.move_to(50, 70)
    context.show_text(
        f"MAC: {mac} | Type: {'Unicast' if is_unicast else 'Multicast'} | Admin: {'Global' if is_global else 'Local'}")

    if vendor:
        context.move_to(50, 95)
        context.show_text(f"Vendor: {vendor}")

    # Draw initial arrow to q0
    context.set_source_rgb(*arrow_color)
    context.set_line_width(2)
    initial_x = start_x - 50
    context.move_to(initial_x, y)
    context.line_to(start_x - state_radius, y)

    # Draw arrowhead
    arrow_size = 10
    context.move_to(start_x - state_radius, y)
    context.line_to(start_x - state_radius - arrow_size, y - arrow_size / 2)
    context.move_to(start_x - state_radius, y)
    context.line_to(start_x - state_radius - arrow_size, y + arrow_size / 2)
    context.stroke()

    # Draw "start" label
    context.set_font_size(12)
    context.move_to(initial_x - 30, y - 10)
    context.show_text("start")

    # Draw all states and transitions
    current_x = start_x

    for i in range(num_states + 1):  # include the final state
        is_final = (i == num_states)

        # Draw state circle (double for final state)
        context.set_source_rgb(*state_color)

        if is_final:
            # Draw double circle for final state
            context.arc(current_x, y, state_radius, 0, 2 * math.pi)
            context.fill_preserve()
            context.set_source_rgb(1, 1, 1)
            context.set_line_width(2)
            context.stroke_preserve()
            context.set_source_rgb(*state_color)
            context.arc(current_x, y, state_radius - 5, 0, 2 * math.pi)
            context.fill()
        else:
            context.arc(current_x, y, state_radius, 0, 2 * math.pi)
            context.fill()

        # Draw state label
        context.set_source_rgb(*text_color)
        context.select_font_face("Arial", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_BOLD)
        context.set_font_size(14)
        state_label = f"q{i}" if not is_final else f"q{i} (final)"

        text_extents = context.text_extents(state_label)
        text_x = current_x - (text_extents.width / 2 + text_extents.x_bearing)
        text_y = y - (text_extents.height / 2 + text_extents.y_bearing)
        context.move_to(text_x, text_y)
        context.show_text(state_label)

        if not is_final:
            next_x = current_x + spacing

            # Draw transition label
            context.set_source_rgb(*transition_color)
            context.set_font_size(14)
            transition_label = transitions[i]

            label_x = current_x + (next_x - current_x) / 2 - 5
            label_y = y - 20
            context.move_to(label_x, label_y)
            context.show_text(transition_label)

            # Draw arrow
            context.set_source_rgb(*arrow_color)
            context.set_line_width(2)
            arrow_start = current_x + state_radius
            arrow_end = next_x - state_radius

            context.move_to(arrow_start, y)
            context.line_to(arrow_end, y)
            context.stroke()

            # Draw arrow head
            arrow_size = 8
            context.move_to(arrow_end, y)
            context.line_to(arrow_end - arrow_size, y - arrow_size / 2)
            context.move_to(arrow_end, y)
            context.line_to(arrow_end - arrow_size, y + arrow_size / 2)
            context.stroke()

            current_x = next_x


def is_valid_mac(mac: str) -> bool:
    """Check if MAC address format is valid"""
    mac_patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
        r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$',
        r'^([0-9A-Fa-f]{12})$'
    ]
    return any(re.match(pattern, mac) for pattern in mac_patterns)


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to standard colon-separated format"""
    clean_mac = re.sub(r'[^0-9A-Fa-f]', '', mac)
    return ':'.join([clean_mac[i:i + 2] for i in range(0, len(clean_mac), 2)]).upper()


def analyze_mac(mac: str) -> Tuple[bool, bool, Optional[str]]:
    """Analyze MAC address properties"""
    first_octet = int(mac.split(':')[0], 16)
    is_unicast = (first_octet & 0b00000001) == 0
    is_global = (first_octet & 0b00000010) == 0

    # Lookup vendor using mac_vendor_lookup library
    lookup = MacLookup()
    try:
        vendor = lookup.lookup(mac)
    except (VendorNotFoundError, ValueError):
        vendor = "Unknown"

    return is_unicast, is_global, vendor


def get_system_mac() -> Optional[str]:
    """Try to get the system's MAC address"""
    try:
        if subprocess.os.name == 'nt':
            result = subprocess.check_output(['getmac'], text=True)
            lines = result.strip().split('\n')
            for line in lines:
                if "Device" not in line and "-" in line:
                    mac = line.split()[0]
                    if is_valid_mac(mac):
                        return normalize_mac(mac)
        else:
            result = subprocess.check_output(['ifconfig'], text=True)
            interfaces = result.split('\n\n')
            for interface in interfaces:
                if 'ether' in interface.lower():
                    for line in interface.split('\n'):
                        if 'ether' in line.lower():
                            mac = line.strip().split()[-1]
                            if is_valid_mac(mac):
                                return normalize_mac(mac)
    except:
        return None
    return None


def calculate_surface_size(mac: str) -> Tuple[int, int]:
    """Calculate optimal surface size based on MAC address length"""
    transition_count = len(mac.replace(":", "")) + mac.count(":")  # Total characters
    min_width = 800
    base_width = transition_count * 100
    width = max(min_width, base_width) + 200  # Add padding
    return (width, 400)  # Fixed height


def main():
    history = []

    print("MAC Address Finite Automaton Analyzer")
    print("Enter a MAC address (or 'quit' to exit)")
    print("Valid formats: 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E or 001A2B3C4D5E")

    while True:
        mac_input = input("\nMAC Address: ").strip()

        if mac_input.lower() == 'quit':
            break

        if not is_valid_mac(mac_input):
            print("Invalid MAC address format. Please try again.")
            continue

        mac = normalize_mac(mac_input)
        history.append(mac)
        is_unicast, is_global, vendor = analyze_mac(mac)

        print("\nMAC Address Analysis:")
        print(f"Normalized: {mac}")
        print(f"Type: {'Unicast' if is_unicast else 'Multicast'}")
        print(f"Administration: {'Globally unique' if is_global else 'Locally administered'}")
        print(f"Vendor: {vendor if vendor else 'Unknown'}")

        # Calculate dynamic surface size
        width, height = calculate_surface_size(mac)
        surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, width, height)
        draw_nfa_diagram(surface, mac, is_unicast, is_global, vendor)

        filename = f"mac_automaton_{len(history)}.png"
        surface.write_to_png(filename)
        print(f"\nFinite automaton diagram saved as {filename}")

        # Offer to check system MAC
        check_system = input("\nCheck your system's MAC address? (yes/no): ").lower()
        if check_system == 'yes':
            system_mac = get_system_mac()
            if system_mac:
                print(f"\nSystem MAC: {system_mac}")
                if system_mac in history:
                    print("Already analyzed this MAC.")
                else:
                    analyze = input("Analyze this MAC? (yes/no): ").lower()
                    if analyze == 'yes':
                        history.append(system_mac)
                        is_unicast, is_global, vendor = analyze_mac(system_mac)
                        print(f"Type: {'Unicast' if is_unicast else 'Multicast'}")
                        print(f"Administration: {'Global' if is_global else 'Local'}")
                        print(f"Vendor: {vendor if vendor else 'Unknown'}")

                        # Use dynamic sizing for system MAC too
                        width, height = calculate_surface_size(system_mac)
                        surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, width, height)
                        draw_nfa_diagram(surface, system_mac, is_unicast, is_global, vendor)
                        filename = "mac_automaton_system.png"
                        surface.write_to_png(filename)
                        print(f"\nSystem MAC automaton diagram saved as {filename}")
            else:
                print("Could not determine system MAC address.")

    print("\nAnalysis History:")
    for i, mac in enumerate(history, 1):
        print(f"{i}. {mac}")

    print("\nGoodbye!")


if __name__ == "__main__":
    main()