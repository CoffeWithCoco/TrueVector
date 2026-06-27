r"""
Generate a PDF dossier documenting WHY each technique is selected and WHAT
payload it sends, for offline review.

For every technique (T01..T29) it prints:
  - ID, name, send-order tier (stealth -> loud) and rank
  - The threat / evasion rationale (verbatim from the technique's metadata)
  - Any deploy requirements (hosted infra, spoofed display name, ...)
  - The exact payload: subject + every MIME part (type, filename, size) and,
    for text parts, the decoded content.

Tricky characters in payloads (zero-width spaces, Cyrillic/Greek homoglyphs,
HTML entities) are REVEALED as \uXXXX so a reviewer can see the evasion instead
of having them silently rendered or replaced.

Run:  .venv\Scripts\python.exe scripts\generate_techniques_dossier.py
Output: data\TrueVector_techniques_dossier.pdf
"""
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from app.techniques.registry import load_all, send_rank
from app.techniques.base import RuntimeContext

OUT = os.path.join("data", "TrueVector_techniques_dossier.pdf")

# Send-order tiers (from registry.SEND_ORDER) — used to explain the selection
# strategy: stealthiest payloads first, loudest/basic-signature last.
TIERS = {
    "T16": "1 - Content/URL obfuscation & HTML smuggling",
    "T17": "1 - Content/URL obfuscation & HTML smuggling",
    "T29": "1 - Content/URL obfuscation & HTML smuggling",
    "T27": "1 - Content/URL obfuscation & HTML smuggling",
    "T26": "1 - Content/URL obfuscation & HTML smuggling",
    "T06": "1 - Content/URL obfuscation & HTML smuggling",
    "T13": "1 - Content/URL obfuscation & HTML smuggling",
    "T07": "1 - Content/URL obfuscation & HTML smuggling",
    "T14": "1 - Content/URL obfuscation & HTML smuggling",
    "T01": "1 - Content/URL obfuscation & HTML smuggling",
    "T24": "1 - Content/URL obfuscation & HTML smuggling",
    "T22": "1 - Content/URL obfuscation & HTML smuggling",
    "T11": "1 - Content/URL obfuscation & HTML smuggling",
    "T12": "2 - Identity / behaviour (spoof, BEC, QR, calendar)",
    "T23": "2 - Identity / behaviour (spoof, BEC, QR, calendar)",
    "T28": "2 - Identity / behaviour (spoof, BEC, QR, calendar)",
    "T08": "2 - Identity / behaviour (spoof, BEC, QR, calendar)",
    "T18": "3a - Evasive attachments",
    "T03": "3a - Evasive attachments",
    "T02": "3a - Evasive attachments",
    "T04": "3a - Evasive attachments",
    "T15": "3a - Evasive attachments",
    "T20": "3b - Alternative-format malware",
    "T21": "3b - Alternative-format malware",
    "T19": "3b - Alternative-format malware",
    "T25": "3b - Alternative-format malware",
    "T10": "4 - Known-bad URL reputation / macro / EICAR signature",
    "T05": "4 - Known-bad URL reputation / macro / EICAR signature",
    "T09": "4 - Known-bad URL reputation / macro / EICAR signature",
}

# Extended rationale in Spanish (the only part the operator reads in Spanish;
# everything else in the dossier stays in English). Each entry expands on the
# technique's threat: what the evasion is, how it works, and which gateway control
# / analysis layer it probes. Falls back to the English meta.threat if missing.
RATIONALE_ES = {
    "T01": (
        "El cuerpo HTML del correo se envía codificado en Base64 en lugar de en texto claro. "
        "Muchos gateways aplican análisis léxico (regex, firmas, detección de marcas y enlaces) "
        "directamente sobre el HTML; si el contenido viaja en Base64, esa inspección superficial no "
        "encuentra nada hasta que el cliente de correo lo decodifica y lo muestra. Mide si el gateway "
        "decodifica las partes Base64 antes de analizarlas o si se queda en la inspección del texto "
        "plano, dejando pasar phishing 'oculto' a plena vista."
    ),
    "T02": (
        "Se adjunta un archivo HTML de phishing dentro de un ZIP. El objetivo es evadir la inspección "
        "de adjuntos: algunos gateways no descomprimen los contenedores ZIP para analizar lo que llevan "
        "dentro, así que el HTML malicioso pasa el filtro. Al abrirlo, la víctima extrae y ejecuta el "
        "HTML en su navegador, fuera del control del gateway. Prueba si el motor de adjuntos inspecciona "
        "el interior de los archivos comprimidos."
    ),
    "T03": (
        "Se adjunta directamente un archivo .html de phishing. Cuando la víctima lo abre, se renderiza "
        "localmente en su navegador desde el disco (origen file://), de modo que el gateway —que solo vio "
        "un adjunto— no interviene en el momento del clic y los filtros de URL / Safe Links no se aplican "
        "a una página servida en local. Prueba si el gateway bloquea o neutraliza adjuntos HTML, un vector "
        "clásico de robo de credenciales."
    ),
    "T04": (
        "Se adjunta una imagen vectorial SVG que contiene JavaScript. El SVG no es una imagen inerte: es "
        "XML que el navegador ejecuta, así que puede correr scripts (XSS, redirección, robo de datos) al "
        "abrirse. Muchos filtros tratan los .svg como imágenes inofensivas y no inspeccionan su script. "
        "Prueba si el gateway detecta y bloquea SVG con contenido activo."
    ),
    "T05": (
        "Documento de Word habilitado para macros (.docm), el vector clásico de entrega de malware vía "
        "macros de Office. Aunque Microsoft ya bloquea por defecto las macros de archivos descargados de "
        "Internet, sigue siendo una prueba imprescindible: mide si el gateway detecta y bloquea/limpia los "
        "documentos macro-enabled antes de que lleguen al buzón. Es una técnica 'ruidosa' (firma muy "
        "conocida), por eso se envía de las últimas."
    ),
    "T06": (
        "Se insertan caracteres de ancho cero (U+200B) dentro de las URLs y los nombres de marca. Para el "
        "usuario el enlace se ve y funciona igual, pero para el motor del gateway la cadena queda 'rota' y "
        "sus expresiones regulares de detección de dominios/marcas no casan. Prueba si el gateway normaliza "
        "(elimina los caracteres invisibles) antes de analizar las URLs, o si una simple inserción de "
        "Unicode invisible basta para evadir la detección léxica."
    ),
    "T07": (
        "Usa la etiqueta HTML <base> para partir la URL maliciosa en dos: el gateway analiza solo el "
        "fragmento relativo (p. ej. '/t07', inofensivo) mientras el cliente de correo combina <base> + "
        "fragmento y resuelve la URL completa y maliciosa. Es la técnica 'baseStriker', que evadió a varios "
        "gateways líderes. Prueba si el analizador de enlaces resuelve <base> igual que lo hace el cliente."
    ),
    "T08": (
        "Invitación de calendario (.ics). Estas invitaciones a menudo se añaden automáticamente al "
        "calendario del usuario y transportan URLs y texto que muchos gateways no inspeccionan con el mismo "
        "rigor que un correo normal. Prueba si el gateway analiza el contenido de los .ics y aplica "
        "reputación / Safe Links a los enlaces que llevan dentro."
    ),
    "T09": (
        "Adjunta el fichero de prueba EICAR, el estándar de la industria para verificar que un antivirus "
        "está activo (no es malware real, pero todo motor AV debe detectarlo). Es la comprobación más básica "
        "y directa: si el EICAR llega al buzón, el motor antivirus del gateway no está escaneando los "
        "adjuntos. Por ser una firma 100% conocida es la técnica más 'ruidosa', y se envía la última para no "
        "contaminar la reputación del remitente durante el resto del run."
    ),
    "T10": (
        "En lugar de adjuntar el EICAR, se enlaza a él (eicar.org). Aquí no se prueba el antivirus de "
        "adjuntos sino la reputación y el análisis de URLs: el gateway debería reconocer que el enlace lleva "
        "a contenido detectable por AV y bloquearlo o reescribirlo. Prueba la capa de reputación de URLs y la "
        "detonación de enlaces (Safe Links / tiempo de clic)."
    ),
    "T11": (
        "El correo carga imágenes desde un servidor externo (hotlinking). Esas imágenes remotas permiten "
        "balizas de seguimiento (confirmar que el correo se abrió, la IP, el cliente) y filtración de datos "
        "vía parámetros de URL. El gateway debería bloquear o 'proxyficar' (reescribir a través de su propio "
        "proxy) las imágenes externas para impedir el beaconing. Prueba el tratamiento de imágenes remotas "
        "(Capa 5)."
    ),
    "T12": (
        "El nombre visible del remitente imita a una marca de confianza (p. ej. 'PayPal Security Team') "
        "aunque el dominio real es otro. La mayoría de usuarios solo miran el nombre, no la dirección. "
        "Mantenemos la dirección autenticada real (para que el proveedor no rechace el envío) y solo "
        "suplantamos el display name, que es justo lo que hace un atacante real. Prueba si el gateway / "
        "anti-phishing detecta la suplantación de identidad y avisa al usuario (banner o cuarentena)."
    ),
    "T13": (
        "La URL usa caracteres Unicode visualmente idénticos a letras latinas (cirílicas o griegas) — por "
        "ejemplo la letra cirílica U+0430, idéntica a la 'a' latina, dentro de 'paypal.com'. Al ojo humano la URL parece legítima, "
        "pero es otro dominio, y evade la reputación basada en cadenas ASCII. Prueba si el gateway hace "
        "normalización / punycode y detecta dominios homoglyph (ataque IDN)."
    ),
    "T14": (
        "Se incluye una URL como texto plano, sin etiqueta <a>. Algunos gateways solo analizan los enlaces "
        "que aparecen en atributos href y pasan por alto las URLs literales escritas en el texto, que el "
        "cliente de correo autolinka igualmente y el usuario puede copiar. Prueba si el análisis de enlaces "
        "cubre también las URLs en texto plano."
    ),
    "T15": (
        "Contenido 'políglota': válido como varios tipos MIME a la vez, con scripts escondidos en "
        "comentarios HTML que algunos parsers de gateway no inspeccionan. Aprovecha la ambigüedad de formato "
        "para que el analizador interprete el fichero de una forma (inofensiva) y el cliente de otra "
        "(ejecutable). Prueba la robustez del parser del gateway ante contenido deliberadamente ambiguo."
    ),
    "T16": (
        "Adjunto HTML que, al abrirse, construye y autodescarga un ejecutable en el navegador usando la "
        "Blob API de JavaScript ('HTML smuggling'). El fichero malicioso nunca cruza el gateway como adjunto "
        "independiente: se ensambla localmente en la máquina de la víctima a partir de datos embebidos. "
        "Prueba si el gateway detecta el patrón de smuggling dentro del HTML en lugar de buscar solo ficheros "
        "adjuntos."
    ),
    "T17": (
        "Variante del smuggling: en vez de adjuntar el HTML, se enlaza a una página (alojada en "
        "infraestructura que tú controlas) que genera y entrega el payload vía Blob API en el navegador de "
        "la víctima. El gateway solo ve una URL; el fichero se crea íntegramente en el cliente. Prueba si la "
        "reputación / detonación de URLs detecta páginas de smuggling. Requiere configurar tu servidor en "
        "Ajustes -> Payload hosting."
    ),
    "T18": (
        "ZIP cifrado con contraseña (cifrado PKZIP tradicional) y la contraseña escrita en el cuerpo del "
        "correo. El gateway no puede descifrar ni escanear el contenido, pero el usuario sí lo abre con la "
        "clave indicada. Es un vector activísimo en campañas de ransomware. Prueba cómo trata el gateway los "
        "adjuntos cifrados que no puede inspeccionar: ¿los bloquea, los marca, o los deja pasar?"
    ),
    "T19": (
        "Imagen de disco .iso. Windows 10+ monta los .iso con doble clic, sin necesidad de extraerlos, y "
        "muchos gateways no inspeccionan el contenido interno de las imágenes de disco. Fue el vector "
        "dominante de Emotet/Qakbot en 2021-2022 precisamente por eso. Prueba si el gateway analiza el "
        "interior de los contenedores .iso."
    ),
    "T20": (
        "Fichero de OneNote (.one), que puede incrustar ejecutables y scripts clicables. Se disparó como "
        "vector en 2022-2023 cuando Microsoft bloqueó las macros de Office por defecto, y muchos gateways no "
        "parsean del todo el formato OneNote. Prueba si el gateway entiende y analiza adjuntos .one."
    ),
    "T21": (
        "PDF con una acción JavaScript (OpenAction) que se ejecuta al abrir el documento, sin interacción "
        "del usuario. El gateway debe detectar y bloquear el JS embebido en los PDFs. Prueba la inspección "
        "profunda de PDFs, no solo su reputación o su extensión."
    ),
    "T22": (
        "El enlace se enruta a través de un redirector abierto en un dominio de máxima reputación "
        "(google.com/url?q=...) para disfrazar el destino real. El gateway ve 'google.com' (de confianza) y "
        "puede no seguir la cadena de redirección hasta el destino malicioso. Prueba si el análisis de URLs "
        "sigue los redirects en dominios de confianza en lugar de fiarse del primer salto."
    ),
    "T23": (
        "El From muestra un dominio aparentemente legítimo pero el Reply-To apunta a un dominio del "
        "atacante: cuando la víctima responde, su respuesta va al atacante. Es el núcleo del fraude BEC "
        "(Business Email Compromise / fraude del CEO). Prueba si el gateway detecta la discrepancia "
        "From / Reply-To y la marca como sospechosa."
    ),
    "T24": (
        "Se envía un fichero HTML declarado con Content-Type: image/gif. Los gateways que confían en el tipo "
        "MIME declarado sin verificar los 'magic bytes' reales del contenido no analizarán el HTML ni su "
        "JavaScript, creyendo que es una imagen inofensiva. Prueba si el gateway valida el contenido real "
        "frente al tipo declarado."
    ),
    "T25": (
        "Acceso directo de Windows (.lnk) con argumentos de línea de comandos que ejecutan comandos "
        "arbitrarios, empaquetado en un ZIP para esquivar los filtros sobre .lnk adjuntos directamente. Muy "
        "común tras el bloqueo de macros. Prueba si el gateway inspecciona el interior del ZIP y detecta el "
        ".lnk peligroso."
    ),
    "T26": (
        "La URL se codifica como entidades HTML (&#x68;&#x74;&#x74;&#x70;...). Los parsers de URL que no "
        "decodifican las entidades antes de analizar no detectan ningún enlace en absoluto. Prueba si el "
        "gateway decodifica las entidades HTML antes de su análisis de enlaces."
    ),
    "T27": (
        "El atributo href va vacío; el JavaScript ensambla la URL real a partir de atributos data-* al hacer "
        "clic. Los escáneres estáticos no encuentran ninguna URL en el HTML porque solo existe en tiempo de "
        "ejecución. Prueba si el gateway detecta enlaces construidos dinámicamente o solo los estáticos."
    ),
    "T28": (
        "La URL maliciosa se codifica en una imagen de código QR incrustada en el cuerpo ('quishing'). Los "
        "gateways no hacen OCR ni leen QRs, así que ningún motor de reputación de URLs detecta el enlace; la "
        "víctima lo escanea con el móvil, a menudo fuera del perímetro corporativo. Prueba si el gateway "
        "analiza el contenido de las imágenes QR. Requiere configurar tu servidor en Ajustes -> Payload "
        "hosting."
    ),
    "T29": (
        "Enlace a un payload detectable por AV (EICAR) alojado en Azure Blob / AWS S3. Como la URL vive en "
        "un dominio de Microsoft/Amazon que proxies, allowlists de VPN y filtros por categoría tratan como "
        "de confianza, los controles basados en reputación suelen evadirse ('living off trusted sites'). "
        "Prueba si el gateway inspecciona el contenido real alojado en nubes de confianza en lugar de fiarse "
        "del dominio. Requiere configurar la URL en Ajustes -> Payload hosting."
    ),
}

# Map a few typographic characters to ASCII for readability; everything else
# non-ASCII is revealed as \uXXXX so hidden evasion characters are visible.
_TYPO = {
    "—": "-", "–": "-", "‘": "'", "’": "'",
    "“": '"', "”": '"', "…": "...", "→": "->",
    " ": " ",
}


def reveal(s: str, limit: int = 2200) -> str:
    """Return an ASCII-safe rendering that exposes non-ASCII / hidden chars.
    Used for PAYLOAD content, where hidden evasion characters must be visible."""
    out = []
    for ch in s:
        if ch in "\n\t":
            out.append(ch)
            continue
        o = ord(ch)
        if 32 <= o < 127:
            out.append(ch)
        elif ch in _TYPO:
            out.append(_TYPO[ch])
        else:
            out.append(f"\\u{o:04x}")
    text = "".join(out)
    if len(text) > limit:
        text = text[:limit] + "\n... [truncated]"
    return text


def latin(s: str) -> str:
    """Render human prose (the Spanish rationale) keeping accents/punctuation.
    Helvetica is Latin-1; Spanish accents (á é í ó ú ñ ü ¿ ¡) all fit, so unlike
    reveal() we do NOT escape them — only normalise typographic chars."""
    for k, v in _TYPO.items():
        s = s.replace(k, v)
    return s.encode("latin-1", errors="replace").decode("latin-1")


def part_body(part):
    """Decode a MIME part for display. Returns (kind, text) where kind is
    'text' (show content) or 'binary' (show metadata + magic bytes)."""
    try:
        raw = part.get_payload(decode=True) or b""
    except Exception:
        raw = b""
    ct = part.get_content_type()
    text_like = ct.startswith("text/") or ct in (
        "application/svg+xml", "application/html",
    ) or (part.get_filename() or "").lower().endswith((".ics", ".com", ".svg", ".html", ".htm"))
    if text_like:
        try:
            return "text", raw.decode("utf-8", errors="replace")
        except Exception:
            pass
    # Binary: show size + first bytes (magic) so the format is identifiable.
    head = " ".join(f"{b:02x}" for b in raw[:24])
    return "binary", f"[binary, {len(raw)} bytes]  magic: {head}"


class Dossier(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "", 7)
        self.set_text_color(150)
        self.cell(0, 6, "TrueVector - Technique selection & payload dossier", align="L")
        self.cell(0, 6, f"p.{self.page_no()}", align="R")
        self.ln(8)
        self.set_text_color(0)


def mc(pdf, height, txt, conv=reveal):
    """multi_cell that always starts at the left margin and advances to the
    next line (avoids fpdf2's 'not enough horizontal space' after w=0 cells).
    `conv` selects the text transform: reveal() for payloads, latin() for prose."""
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(pdf.epw, height, conv(txt), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def h(pdf, txt, size=10, style="B", gap=1.5, color=(17, 24, 39), conv=reveal):
    pdf.set_font("Helvetica", style, size)
    pdf.set_text_color(*color)
    mc(pdf, size * 0.5 + 1.5, txt, conv=conv)
    pdf.ln(gap)


def body(pdf, txt, size=8.5, color=(31, 41, 55), mono=False, conv=reveal):
    pdf.set_font("Courier" if mono else "Helvetica", "", size)
    pdf.set_text_color(*color)
    mc(pdf, size * 0.55 + 1.3, txt, conv=conv)


def main():
    ctx = RuntimeContext(
        web_base_url="https://payload.example.com",
        cloud_payload_url="https://acct.blob.core.windows.net/files/document.html",
    )
    techs = load_all()

    pdf = Dossier(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)

    # ── Cover ───────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.ln(20)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(17, 24, 39)
    mc(pdf, 11, "Technique Selection &\nPayload Dossier")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(80)
    mc(pdf, 6, "TrueVector - Email Attack Surface Validator")
    pdf.set_font("Helvetica", "", 9)
    mc(pdf, 5.5, f"Generated {datetime.now():%Y-%m-%d %H:%M}   |   {len(techs)} techniques")
    pdf.ln(6)

    intro = (
        "This document explains WHY each technique is included and WHAT exactly it "
        "sends, so the catalog can be reviewed before launching against a mailbox.\n\n"
        "Selection principle. Each technique maps to a distinct, real-world gateway "
        "evasion or threat class (content/URL obfuscation, HTML smuggling, evasive or "
        "alternative-format attachments, identity/BEC spoofing, and known-bad AV/URL "
        "signatures). Together they probe the five analysis layers: delivery, gateway "
        "verdict (SCL/auth), body transformations (Safe Links/banners), attachments "
        "(stripped vs intact) and images.\n\n"
        "Send order. Techniques are sent stealthiest-first, loudest-last (Tier 1 -> 4). "
        "A brand-new external sender that bursts odd messages at one mailbox is itself "
        "suspicious; sending the subtle vectors before the obviously-malicious ones "
        "(macros, EICAR) ensures each is measured on its own payload merits before the "
        "sender's reputation can be burned mid-run.\n\n"
        "Payloads are inert: links point to .invalid/test hosts or the EICAR test "
        "string; no real malware is included. Tricky characters (zero-width spaces, "
        "Cyrillic/Greek homoglyphs, HTML entities) are shown escaped as \\uXXXX so the "
        "evasion is visible rather than silently rendered."
    )
    body(pdf, intro, size=9.5)

    # ── One section per technique ───────────────────────────────────────────
    for t in techs:
        m = t.meta
        pdf.add_page()

        # Title bar
        pdf.set_fill_color(17, 24, 39)
        pdf.set_text_color(255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_x(pdf.l_margin)
        pdf.cell(pdf.epw, 9, reveal(f"  {m.id}  -  {m.name}"), fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        pdf.set_text_color(90)
        pdf.set_font("Helvetica", "", 8)
        tier = TIERS.get(m.id, "-")
        mc(pdf, 4.6, f"Send tier: {tier}    |    send rank: {send_rank(m.id)} (0 = sent first / stealthiest)")
        pdf.ln(2)

        # Rationale: the only section in Spanish (for the operator to read).
        h(pdf, "Por qué se prueba esta técnica", size=10, conv=latin)
        body(pdf, RATIONALE_ES.get(m.id, m.threat), size=9, conv=latin)
        pdf.ln(2)

        reqs = []
        if m.expected_attachments:
            reqs.append(f"Expected attachment(s): {', '.join(m.expected_attachments)}")
        if m.expected_images:
            reqs.append("Expects external/inline images")
        if m.spoof_from_name:
            reqs.append(f"Spoofed From display name: \"{m.spoof_from_name}\"")
        if m.requires:
            reqs.append(f"Requires deploy config: {m.requires} (hosted payload infrastructure)")
        if reqs:
            h(pdf, "Delivery requirements / notes", size=10)
            for r in reqs:
                body(pdf, f"- {r}", size=9)
            pdf.ln(2)

        # Payload
        h(pdf, "Payload sent", size=10)
        try:
            msg = t.render(ctx)
        except Exception as e:
            body(pdf, f"[could not render payload: {e}]", size=9)
            continue
        body(pdf, f"Subject: {msg.get('Subject')}", size=9)
        for extra_hdr in ("Reply-To", "From"):
            if msg.get(extra_hdr):
                body(pdf, f"{extra_hdr}: {msg.get(extra_hdr)}", size=9)
        pdf.ln(1.5)

        parts = list(msg.walk()) if msg.is_multipart() else [msg]
        for part in parts:
            if part.is_multipart():
                continue
            ct = part.get_content_type()
            fn = part.get_filename()
            cte = part.get("Content-Transfer-Encoding")
            label = f"MIME part: {ct}" + (f"  (filename: {fn})" if fn else "") + f"   [{cte}]"
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_text_color(37, 99, 235)
            mc(pdf, 4.8, label)
            kind, content = part_body(part)
            pdf.set_draw_color(220)
            body(pdf, content, size=8, mono=True, color=(55, 65, 81))
            pdf.ln(1.5)

    os.makedirs("data", exist_ok=True)
    pdf.output(OUT)
    print(f"Wrote {OUT}  ({os.path.getsize(OUT)} bytes)")


if __name__ == "__main__":
    main()
