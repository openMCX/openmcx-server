#!/usr/bin/env python3
"""Build the MCX over IMS and 5G functional architecture figure.

Writes 5g-ims-mcx-functional-entities.svg (editable) beside this script and renders it to
5g-ims-mcx-functional-entities.png for the slides with librsvg and cairo. Drawing only: the
reference-point labels are illustrative and carry no 3GPP behaviour.
"""

import ctypes
from html import escape
from pathlib import Path
from xml.etree import ElementTree as ET

CANVAS_WIDTH, CANVAS_HEIGHT = 3400, 2420
svg_parts = []


# ------------------------------------------------------------------------------
def add(element):
    """Append one SVG element to the figure."""
    svg_parts.append(element)


# Keep the layer colors, but give pale box outlines enough contrast at slide size.
BOX_STROKES = {
    '#bccbdc': '#879db5',
    '#b2d6c5': '#77ae95',
    '#efc59f': '#d3935e',
    '#cdb8ed': '#a382cf',
    '#b6ccec': '#83a7d5',
    '#e7bd9b': '#cc8e5e',
    '#e9c5a7': '#d49c70',
    '#d3c0eb': '#aa8bcc',
    '#bfd1eb': '#8daed7',
    '#c7d8ef': '#91b2dc',
    '#c9e4d8': '#91c6ae',
    '#9bcdb6': '#70b28f',
    '#e8b48e': '#ca8253',
    '#efd1b8': '#d9a079',
    '#dc9a68': '#bc7541',
    '#d3bce9': '#ab89ce',
    '#aec8e8': '#86aad3',
}


# ------------------------------------------------------------------------------
def rect(left, top, box_width, box_height, fill, stroke='none', radius=0, sw=1):
    """Draw a rectangle; a known pale stroke colour is replaced by its darker BOX_STROKES outline."""
    stroke = BOX_STROKES.get(stroke, stroke)
    add(
        f'<rect x="{left}" y="{top}" width="{box_width}" height="{box_height}" rx="{radius}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'
    )


# ------------------------------------------------------------------------------
def text(text_x, text_y, content, size=23, color='#1b2a41', weight=500, anchor='start'):
    """Draw a text label at the given anchor point."""
    add(
        f'<text x="{text_x}" y="{text_y}" fill="{color}" font-family="DejaVu Sans, Arial, sans-serif" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}">{escape(content)}</text>'
    )


# ------------------------------------------------------------------------------
def line(x1, y1, x2, y2, color='#65758b', sw=3, dash=None):
    """Draw a straight line, dashed when dash is given."""
    dash_attribute = f' stroke-dasharray="{dash}"' if dash else ''
    add(
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}" stroke-linecap="round"{dash_attribute}/>'
    )


# ------------------------------------------------------------------------------
def path(path_data, color='#65758b', sw=3, dash=None):
    """Draw an SVG path from its path data, dashed when dash is given."""
    dash_attribute = f' stroke-dasharray="{dash}"' if dash else ''
    add(
        f'<path d="{path_data}" fill="none" stroke="{color}" stroke-width="{sw}" stroke-linejoin="round" stroke-linecap="round"{dash_attribute}/>'
    )


# ------------------------------------------------------------------------------
def badge(center_x, center_y, label, color, fill='#fff', size=18):
    """Draw a rounded badge (a reference-point label) centred on the given point."""
    box_width = max(62, len(label) * size * 0.65 + 24)
    rect(center_x - box_width / 2, center_y - 19, box_width, 38, fill, color, 19, 1.6)
    text(center_x, center_y + 6, label, size, color, 750, 'middle')


# ------------------------------------------------------------------------------
def card(left, top, box_width, box_height, title, sub=None, fill='#fff', stroke='#d6e1ed', ts=25):
    """Draw a function box with its title and an optional subtitle."""
    rect(left, top, box_width, box_height, fill, stroke, 14, 2)
    text(left + 19, top + 39, title, ts, '#182b43', 750)
    if sub:
        text(left + 19, top + 70, sub, 17, '#52657c')


add(
    f'<svg xmlns="http://www.w3.org/2000/svg" width="{CANVAS_WIDTH}" height="{CANVAS_HEIGHT}" viewBox="0 0 {CANVAS_WIDTH} {CANVAS_HEIGHT}" role="img" aria-labelledby="title desc">'
)
add('<title id="title">MCX over IMS and 5G: three-column functional architecture</title>')
add(
    '<desc id="desc">The left column is a UE containing MCX, IMS and 5G clients. The middle column is separate 5G NG-RAN access. The right column stacks MCX above IMS above 5G Core. It shows the MC service server to PCF N5 policy path and two location sources: UE LMC reports to MCX LMS, and LMS obtains operator location through NEF, GMLC, AMF and LMF.</desc>'
)
rect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT, '#f5f8fc')
rect(0, 0, CANVAS_WIDTH, 112, '#12243c')
text(55, 70, 'MCX / IMS / 5G functional architecture', 43, '#fff', 800)
text(2110, 68, 'Three columns  ·  5G QoS and named reference points', 23, '#dbeafb')

# Three structural columns, with network layers stacked only in the third.
rect(50, 145, 415, 2170, '#fff', '#bccbdc', 23, 2.3)
rect(495, 145, 405, 2170, '#f3fbf8', '#b2d6c5', 23, 2.3)
rect(930, 145, 2420, 780, '#fff2e8', '#efc59f', 23, 2.2)
rect(930, 950, 2420, 360, '#f2ecff', '#cdb8ed', 23, 2.2)
rect(930, 1335, 2420, 980, '#eaf3ff', '#b6ccec', 23, 2.2)
rect(50, 145, 415, 88, '#243952', radius=22)
rect(50, 207, 415, 26, '#243952')
text(77, 201, 'UE / MCX DEVICE', 29, '#fff', 800)
rect(495, 145, 405, 88, '#177659', radius=22)
rect(495, 207, 405, 26, '#177659')
text(525, 201, '5G ACCESS / NG-RAN', 27, '#fff', 800)
text(965, 206, 'MCX', 38, '#bd5b18', 800)
text(1140, 205, 'Mission-critical service and common-service functions', 23, '#7a5d4b')
text(965, 1011, 'IMS', 38, '#7546b6', 800)
text(1140, 1010, 'SIP registration and service routing', 23, '#66577a')
text(965, 1395, '5G CORE', 38, '#2362ad', 800)
text(1210, 1394, 'Access control, policy, QoS flows and user-plane delivery', 23, '#526b8c')

# UE stack.
rect(72, 267, 371, 630, '#fff8f2', '#e7bd9b', 17, 2)
text(93, 316, 'MCX CLIENT', 29, '#ad5017', 800)
text(93, 357, 'MCPTT · MCData · MCVideo', 20, '#24364d', 650)
line(93, 379, 421, 379, '#ecc9ae', 2)
text(93, 418, 'SIP signalling UA', 19, '#25364a', 650)
text(93, 453, 'HTTP + common clients', 19, '#25364a', 650)
text(93, 489, 'IdM · group · config', 18, '#52657b')
text(93, 522, 'key · location', 18, '#52657b')
rect(93, 581, 329, 129, '#fff', '#e9c5a7', 11, 1.5)
text(111, 621, 'PTT / data / video media', 18, '#ad5017', 700)
text(111, 657, 'and floor / tx control', 18, '#52657b')
card(93, 730, 329, 96, 'LMC / location', 'UE reports to LMS (CSC-14)', '#fff', '#e9c5a7', 19)
text(93, 865, 'MCX identity + group data', 17, '#52657b')
rect(72, 975, 371, 410, '#f8f5ff', '#d3c0eb', 17, 2)
text(93, 1024, 'IMS USER AGENT', 27, '#7546b6', 800)
text(93, 1067, 'SIP registration', 19, '#25364a', 650)
text(93, 1102, 'Session signalling', 19, '#25364a', 650)
text(93, 1173, 'IMS public/private IDs', 18, '#52657b')
rect(72, 1485, 371, 710, '#f3f8ff', '#bfd1eb', 17, 2)
text(93, 1536, '5G UE', 29, '#2362ad', 800)
text(93, 1579, 'NAS · PDU session', 19, '#25364a', 650)
text(93, 1615, 'QoS rules / QFI', 19, '#25364a', 650)
text(93, 1651, 'NR radio modem', 19, '#25364a', 650)
rect(93, 1910, 329, 190, '#fff', '#c7d8ef', 12, 1.5)
text(111, 1950, 'Service QoS flows', 19, '#2362ad', 700)
text(111, 1984, 'UL packets mapped by UE', 17, '#52657b')
text(111, 2016, 'DL packets from gNB', 17, '#52657b')
text(111, 2048, 'over radio bearers', 17, '#52657b')

# Access has its own full-height column; the gNB lives at its 5G base.
text(523, 288, 'Packets cross this access', 20, '#17664d', 700)
text(523, 322, 'using a 5G PDU session.', 19, '#52657b')
rect(520, 535, 355, 160, '#fff', '#c9e4d8', 13, 1.6)
text(542, 579, 'MCX application traffic', 21, '#17664d', 700)
text(542, 615, 'Logical UE ↔ MCX', 18, '#52657b')
text(542, 650, 'endpoints over 5G IP', 18, '#52657b')
rect(520, 1225, 355, 145, '#fff', '#c9e4d8', 13, 1.6)
text(542, 1268, 'IMS signalling', 21, '#17664d', 700)
text(542, 1305, 'Gm is end-to-end SIP', 18, '#52657b')
text(542, 1338, 'over 5G transport', 18, '#52657b')
rect(520, 1585, 355, 137, '#fff', '#c9e4d8', 13, 1.6)
text(542, 1625, '5G radio access', 21, '#17664d', 700)
text(542, 1660, 'N2 control · N3 user', 18, '#52657b')
card(555, 1740, 310, 155, 'gNB', 'Schedule admitted QoS flows', '#fff', '#9bcdb6', 28)
rect(520, 1920, 355, 155, '#fff', '#c9e4d8', 13, 1.6)
text(542, 1960, 'Optional gNB split', 20, '#17664d', 700)
text(542, 1996, 'F1: CU ↔ DU', 18, '#52657b')
text(542, 2030, 'E1: CU-CP ↔ CU-UP', 18, '#52657b')

# MCX server and common services.
rect(985, 258, 1025, 442, '#fff', '#e8b48e', 17, 2)
text(1012, 304, 'MC SERVICE SERVER (MCX)', 28, '#b65517', 800)
text(1012, 337, 'Application control, floor / transmission control and distribution', 18, '#52657b')
for column_left, title, sub in [
    (1010, 'MCPTT', 'Call + floor'),
    (1338, 'MCData', 'SDS + FD + streams'),
    (1666, 'MCVideo', 'Video + tx control'),
]:
    card(column_left, 374, 314, 110, title, sub, '#fff8f2', '#efd1b8', 24)
card(1010, 531, 615, 111, 'Media + floor / transmission', 'MCPTT-4/7 · MCVideo-4/7', '#fff8f2', '#efd1b8', 22)
card(1666, 531, 314, 111, 'MCX SIP AS', 'Service SIP trigger', '#ffe6d1', '#dc9a68', 22)
text(1012, 678, 'AF role on N5: MCPTT-5 · MCVideo-5 · MCData-5', 17, '#9e4d17', 700)
rect(2040, 258, 1265, 442, '#fff', '#e8b48e', 17, 2)
text(2065, 304, 'COMMON SERVICES', 28, '#b65517', 800)
for column_left, row_top, title in [
    (2063, 347, 'IdMS'),
    (2478, 347, 'CMS'),
    (2893, 347, 'GMS'),
    (2063, 465, 'KMS'),
    (2478, 465, 'LMS'),
    (2893, 465, 'User DB'),
]:
    card(column_left, row_top, 390, 92, title, None, '#fff8f2', '#efd1b8', 22)
text(2065, 675, 'CSC-1/2/4/8/14 · CSC-3/5/9/15 · CSC-13', 17, '#9e4d17', 700)
# MC service server requests and receives location from LMS on CSC-15.
path('M 2010 620 H 2673 V 557', '#b65517', 3, '9 7')
badge(2290, 595, 'CSC-15 / MC server ↔ LMS', '#b65517', size=16)

# MCX logical app paths, common-service HTTP and 5G data-network route.
line(443, 470, 985, 470, '#c26924', 3, '10 7')
badge(736, 435, 'MCPTT-1 · MCData-SDS-1/FD-1 · MCVideo-1', '#b65517', size=15)
line(443, 801, 985, 801, '#c26924', 3, '10 7')
badge(730, 765, 'HTTP-1', '#b65517', size=17)
card(985, 751, 440, 105, 'HTTP proxy', 'Proxied common-service requests', '#fff', '#e8b48e', 22)
path('M 1425 801 H 2450 V 700', '#c26924', 3, '10 7')
badge(1775, 765, 'HTTP-2', '#b65517', size=17)
text(1475, 840, 'UE clients ↔ IdMS / GMS / CMS / KMS / LMS', 18, '#9e4d17', 650)
badge(730, 834, 'CSC-14 / LMC → LMS', '#0b7a81', size=16)
line(2010, 468, 2040, 468, '#c26924', 3, '9 6')
text(1630, 896, 'Server ↔ common services: CSC-3/5/9/15   ·   CMS ↔ user DB: CSC-13', 18, '#9e4d17', 650)
path('M 1480 700 V 728 H 3315 V 1940 H 3240', '#12805a', 4, '13 7')
badge(2830, 726, 'MCX media / data via DN', '#12805a', size=17)
text(3294, 1345, 'IP user plane', 17, '#12805a', 700, 'end')
# Operator-supplied MCX location uses N33/Nnef at the LMS, not a direct LMF API.
path('M 2810 557 V 775 H 3270 V 2200 H 3210', '#0b7a81', 3.5, '11 7')
badge(3070, 775, 'N33 / Nnef location', '#0b7a81', size=17)

# IMS layer: UE SIP, CSCFs, HSS and service triggering.
card(1040, 1035, 300, 145, 'P-CSCF', 'UE-facing SIP proxy', '#fff', '#d3bce9', 27)
card(1460, 1035, 300, 145, 'I-CSCF', 'CSCF selection', '#fff', '#d3bce9', 27)
card(1880, 1035, 300, 145, 'S-CSCF', 'Service triggering', '#fff', '#d3bce9', 27)
card(2360, 1035, 300, 145, 'HSS', 'IMS subscriber data', '#fff', '#d3bce9', 27)
line(443, 1105, 1040, 1105, '#7546b6', 3, '11 7')
badge(740, 1068, 'Gm / SIP-1', '#7546b6', size=18)
line(1340, 1105, 1460, 1105, '#7546b6', 3)
badge(1400, 1069, 'Mw', '#7546b6')
line(1760, 1105, 1880, 1105, '#7546b6', 3)
badge(1820, 1069, 'Mw', '#7546b6')
path('M 1610 1180 V 1245 H 2510 V 1180', '#7546b6', 2.8)
path('M 2030 1180 V 1245', '#7546b6', 2.8)
badge(2260, 1245, 'Cx: I/S-CSCF ↔ HSS', '#7546b6', size=16)
path('M 2030 1035 V 940 H 1823 V 642', '#7546b6', 3, '10 7')
badge(2020, 947, 'ISC / SIP-2', '#7546b6', size=17)
path('M 1610 1035 V 1005 H 1725 V 642', '#ad8bd6', 2, '6 8')
badge(1690, 1008, 'Ma (optional)', '#7546b6', size=15)
text(
    1000,
    1285,
    'IMS handles SIP. MCX common-service HTTP and media use 5G IP connectivity without traversing the SIP core.',
    19,
    '#66577a',
)

# 5GC relationships drawn before the functional boxes.
path('M 300 1740 V 1440 H 1245 V 1545', '#4b79a6', 3, '11 7')
line(443, 1817, 555, 1817, '#12805a', 4)
path('M 865 1790 H 1000 V 1612 H 1090', '#2362ad', 3.4)
path('M 865 1860 H 915 V 2035 H 2265 V 2000', '#12805a', 4)
line(1370, 1610, 1450, 1610, '#2362ad', 3)
line(1740, 1610, 1820, 1610, '#2362ad', 3)
line(2110, 1610, 2190, 1610, '#2362ad', 3)
path('M 1240 1545 V 1515 H 1965 V 1545', '#5d89b6', 2.5)
path('M 1230 1680 V 1775 H 1195 V 1880', '#2362ad', 3)
path('M 1370 1650 H 1415 V 1750 H 1750 V 1850', '#2362ad', 3)
path('M 1955 1680 V 1765 H 1750 V 1850', '#5d89b6', 2.5)
path('M 1740 1850 V 1795 H 3000 V 1770', '#b24663', 3.2)
line(1950, 1920, 2110, 1920, '#2362ad', 3.5)
line(2450, 1920, 2790, 1920, '#12805a', 4)
path('M 1990 700 V 711 H 2725 V 1528 H 3030 V 1545', '#b24663', 4, '14 7')
# Example high-accuracy LCS chain. The existing gNB–AMF N2 path also carries NRPPa.
line(2820, 2200, 2260, 2200, '#0b7a81', 3.5)
path('M 1860 2200 H 1435 V 1570 H 1370', '#0b7a81', 3.5)
path('M 1370 1680 H 1400 V 2240 H 1340', '#0b7a81', 3.5)

# 5GC nodes.
card(1090, 1545, 280, 135, 'AMF', 'Access / mobility', '#fff', '#aec8e8', 27)
card(1450, 1545, 290, 135, 'AUSF', 'Authentication', '#fff', '#aec8e8', 27)
card(1820, 1545, 290, 135, 'UDM', 'Subscription', '#fff', '#aec8e8', 27)
card(2190, 1545, 290, 135, 'UDR', 'Data repository', '#fff', '#aec8e8', 27)
# The small 5QI key is informative and sits near PCF, not inside the MCX layer.
rect(2810, 1365, 430, 142, '#f8fbff', '#aec8e8', 12, 1.7)
text(2830, 1400, 'MCX 5QI examples', 20, '#2362ad', 750)
text(2830, 1435, 'PTT 65  ·  video RT 67', 17, '#25364a', 650)
text(2830, 1465, 'video NRT 4  ·  data 70 opt.', 17, '#25364a', 650)
text(2830, 1495, 'SIP 69  ·  HTTP 8 or better', 17, '#25364a', 650)
rect(2810, 1545, 430, 225, '#fff', '#aec8e8', 14, 2)
text(2830, 1585, 'PCF', 27, '#182b43', 750)
text(2830, 1621, 'Npcf_PolicyAuthorization', 18, '#2362ad', 700)
text(2830, 1653, 'fDescs: flow descriptions', 17, '#52657c')
text(2830, 1683, 'afAppId: application ID', 17, '#52657c')
text(2830, 1714, 'Policy → authorized 5QI / ARP', 17, '#52657c', 650)
text(2830, 1744, 'PCC rule → SMF over N7', 17, '#52657c')
card(1040, 1880, 310, 120, 'NSSF', 'Slice selection', '#fff', '#aec8e8', 25)
card(1590, 1850, 360, 150, 'SMF', 'PDU session / QoS rules', '#fff', '#aec8e8', 27)
card(2110, 1850, 340, 150, 'UPF', 'Enforce MCX flow rules', '#fff', '#aec8e8', 27)
card(2790, 1850, 450, 150, 'DN / DNN', 'Reachable IMS + MCX networks', '#fff', '#aec8e8', 27)

# Network location functions sit in the 5GC, below the session and user-plane row.
text(1000, 2085, '5GS LOCATION SERVICES', 23, '#0b7a81', 800)
text(1580, 2085, 'GMLC/LMF positioning example; NEF may use AMF for cell-level location.', 18, '#52657c')
card(1000, 2135, 340, 135, 'LMF', 'Determines UE position', '#fff', '#aec8e8', 27)
text(1019, 2245, 'LPP / NRPPa via AMF', 17, '#52657c')
card(1860, 2135, 400, 135, 'GMLC', 'LCS gateway + privacy', '#fff', '#aec8e8', 27)
text(1879, 2245, 'Routes authorized location', 17, '#52657c')
card(2820, 2135, 390, 135, 'NEF', 'N33 exposure to MCX LMS', '#fff', '#aec8e8', 27)
text(2839, 2245, 'Location API + authorization', 17, '#52657c')

# Reference-point labels, including distinct QoS control and media path.
badge(505, 1777, 'Uu / DRB', '#12805a', size=16)
badge(765, 1440, 'N1 / NAS', '#4b79a6', size=17)
badge(975, 1578, 'N2 / QoS + NRPPa', '#2362ad', size=16)
badge(1700, 2035, 'N3 / QFI', '#12805a', size=17)
badge(1410, 1581, 'N12', '#2362ad', size=16)
badge(1780, 1581, 'N13', '#2362ad', size=16)
badge(2150, 1581, 'N35', '#2362ad', size=16)
badge(1640, 1515, 'N8', '#5d89b6', size=16)
badge(1250, 1773, 'N22', '#2362ad', size=16)
badge(1530, 1750, 'N11', '#2362ad', size=16)
badge(1940, 1765, 'N10', '#5d89b6', size=16)
badge(2530, 1795, 'N7 / PCC rules', '#b24663', size=17)
badge(2030, 1880, 'N4 / UPF rules', '#2362ad', size=16)
badge(2620, 1880, 'N6 / IP traffic', '#12805a', size=16)
badge(2725, 1018, 'N5 / MC server (AF role) ↔ PCF', '#b24663', size=17)
text(2780, 1265, 'Direct policy path; no IMS SIP hop', 17, '#9c405c', 650)
badge(2535, 2160, 'NL5 / Ngmlc', '#0b7a81', size=16)
badge(1635, 2160, 'NL2 / Namf', '#0b7a81', size=16)
badge(1400, 2085, 'NL1 / Nlmf', '#0b7a81', size=16)
text(
    1000,
    2300,
    'Support: NRF discovery (Nnrf) · NEF exposure (N33 for LCS or indirect QoS) · SCP optional',
    18,
    '#4d6b8f',
)

# Figure legend and scope note.
line(65, 2380, 150, 2380, '#b24663', 4, '13 7')
text(165, 2387, 'QoS policy / control', 18, '#52657b', 650)
line(525, 2380, 610, 2380, '#12805a', 4, '13 7')
text(625, 2387, 'Media / IP user plane', 18, '#52657b', 650)
line(1035, 2380, 1120, 2380, '#7546b6', 4, '13 7')
text(1135, 2387, 'Logical SIP / app reference point', 18, '#52657b', 650)
line(1770, 2380, 1855, 2380, '#0b7a81', 4, '11 7')
text(1870, 2387, '5GS location service', 18, '#52657b', 650)
text(3335, 2387, '5QI alone does not guarantee bit rate; admitted GBR flows provide GFBR.', 18, '#52657b', 500, 'end')
add('</svg>')
target = Path(__file__).resolve().parent / '5g-ims-mcx-functional-entities.svg'
target.write_text('\n'.join(svg_parts) + '\n')
print(target, target.stat().st_size)

root = ET.parse(target).getroot()
width, height = int(root.attrib['width']), int(root.attrib['height'])
png = target.with_suffix('.png')
rsvg = ctypes.CDLL('librsvg-2.so.2')
cairo = ctypes.CDLL('libcairo.so.2')
gobject = ctypes.CDLL('libgobject-2.0.so.0')
rsvg.rsvg_handle_new_from_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
rsvg.rsvg_handle_new_from_file.restype = ctypes.c_void_p
rsvg.rsvg_handle_render_cairo.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
rsvg.rsvg_handle_render_cairo.restype = ctypes.c_int
cairo.cairo_image_surface_create.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
cairo.cairo_image_surface_create.restype = ctypes.c_void_p
cairo.cairo_create.argtypes = [ctypes.c_void_p]
cairo.cairo_create.restype = ctypes.c_void_p
cairo.cairo_surface_write_to_png.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
cairo.cairo_surface_write_to_png.restype = ctypes.c_int
cairo.cairo_destroy.argtypes = [ctypes.c_void_p]
cairo.cairo_surface_destroy.argtypes = [ctypes.c_void_p]
gobject.g_object_unref.argtypes = [ctypes.c_void_p]
handle = rsvg.rsvg_handle_new_from_file(str(target).encode(), None)
assert handle
surface = cairo.cairo_image_surface_create(0, width, height)
ctx = cairo.cairo_create(surface)
assert rsvg.rsvg_handle_render_cairo(handle, ctx)
assert cairo.cairo_surface_write_to_png(surface, str(png).encode()) == 0
cairo.cairo_destroy(ctx)
cairo.cairo_surface_destroy(surface)
gobject.g_object_unref(handle)
print(png, width, height, png.stat().st_size)
