/**
 * Text normalizer — preprocesses input to defeat evasion techniques.
 *
 * Runs BEFORE regex scanning to ensure attackers can't bypass detection
 * using Unicode tricks, encoding, leetspeak, etc.
 *
 * Inspired by: Microsoft Presidio, LLM Guard, rebuff, OWASP guidelines.
 */

// ─── Zero-width & invisible characters ──────────────────────────

const ZERO_WIDTH_CHARS = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD\u034F\u061C\u180E]/g;

// ─── Homoglyph map: visually similar chars → ASCII ──────────────
// Covers Cyrillic, Greek, and other common confusables

const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic → Latin
  '\u0410': 'A', '\u0430': 'a',  // А/а
  '\u0412': 'B', '\u0432': 'b',  // В/в (looks like B)
  '\u0421': 'C', '\u0441': 'c',  // С/с
  '\u0415': 'E', '\u0435': 'e',  // Е/е
  '\u041D': 'H', '\u043D': 'h',  // Н/н
  '\u041A': 'K', '\u043A': 'k',  // К/к
  '\u041C': 'M', '\u043C': 'm',  // М/м
  '\u041E': 'O', '\u043E': 'o',  // О/о
  '\u0420': 'P', '\u0440': 'p',  // Р/р
  '\u0422': 'T', '\u0442': 't',  // Т/т
  '\u0423': 'Y', '\u0443': 'y',  // У/у (looks like Y)
  '\u0425': 'X', '\u0445': 'x',  // Х/х
  '\u0405': 'S', '\u0455': 's',  // Ѕ/ѕ
  '\u0406': 'I', '\u0456': 'i',  // І/і
  '\u0408': 'J', '\u0458': 'j',  // Ј/ј
  // Greek → Latin
  '\u0391': 'A', '\u03B1': 'a',  // Α/α
  '\u0392': 'B', '\u03B2': 'b',  // Β/β
  '\u0395': 'E', '\u03B5': 'e',  // Ε/ε
  '\u0397': 'H', '\u03B7': 'h',  // Η/η
  '\u0399': 'I', '\u03B9': 'i',  // Ι/ι
  '\u039A': 'K', '\u03BA': 'k',  // Κ/κ
  '\u039C': 'M', '\u03BC': 'm',  // Μ/μ
  '\u039D': 'N', '\u03BD': 'n',  // Ν/ν
  '\u039F': 'O', '\u03BF': 'o',  // Ο/ο
  '\u03A1': 'P', '\u03C1': 'p',  // Ρ/ρ
  '\u03A4': 'T', '\u03C4': 't',  // Τ/τ
  '\u03A5': 'Y', '\u03C5': 'y',  // Υ/υ
  '\u03A7': 'X', '\u03C7': 'x',  // Χ/χ
  '\u03A9': 'W',                   // Ω (omega)
  // Full-width → ASCII
  ...Object.fromEntries(
    Array.from({ length: 26 }, (_, i) => [
      String.fromCharCode(0xFF21 + i), // Ａ-Ｚ
      String.fromCharCode(0x41 + i),   // A-Z
    ])
  ),
  ...Object.fromEntries(
    Array.from({ length: 26 }, (_, i) => [
      String.fromCharCode(0xFF41 + i), // ａ-ｚ
      String.fromCharCode(0x61 + i),   // a-z
    ])
  ),
  ...Object.fromEntries(
    Array.from({ length: 10 }, (_, i) => [
      String.fromCharCode(0xFF10 + i), // ０-９
      String.fromCharCode(0x30 + i),   // 0-9
    ])
  ),
};

// ─── Leetspeak map ──────────────────────────────────────────────

const LEET_MAP: Record<string, string> = {
  '0': 'o',
  '1': 'i',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '@': 'a',
  '$': 's',
  '!': 'i',
  '(': 'c',
  '|': 'l',
};

// ─── HTML entity decoder ────────────────────────────────────────

const NAMED_ENTITIES: Record<string, string> = {
  '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"',
  '&apos;': "'", '&nbsp;': ' ', '&tab;': '\t',
};

function decodeHtmlEntities(text: string): string {
  // Decode numeric entities: &#49; &#x31;
  let result = text.replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)));
  result = result.replace(/&#x([0-9a-fA-F]+);/g, (_, code) => String.fromCharCode(parseInt(code, 16)));
  // Decode named entities
  for (const [entity, char] of Object.entries(NAMED_ENTITIES)) {
    result = result.split(entity).join(char);
  }
  return result;
}

// ─── URL decoder ────────────────────────────────────────────────

function decodeUrlEncoding(text: string): string {
  try {
    // Only decode if it looks URL-encoded (contains %XX)
    if (/%[0-9a-fA-F]{2}/.test(text)) {
      return decodeURIComponent(text);
    }
  } catch {
    // Malformed URL encoding — return as-is
  }
  return text;
}

// ─── Base64 detector + decoder ──────────────────────────────────

const BASE64_PATTERN = /(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

function expandBase64(text: string): string {
  const matches = text.match(BASE64_PATTERN);
  if (!matches) return text;

  let expanded = text;
  for (const match of matches) {
    try {
      const decoded = Buffer.from(match, 'base64').toString('utf-8');
      // Only treat as base64 if decoded result is mostly printable ASCII
      if (/^[\x20-\x7E\s]{4,}$/.test(decoded)) {
        expanded += ' ' + decoded;
      }
    } catch {
      // Not valid base64
    }
  }
  return expanded;
}

// ─── Hex string detector + decoder ──────────────────────────────

const HEX_PATTERN = /(?:[0-9a-fA-F]{2}){8,}/g;

function expandHex(text: string): string {
  const matches = text.match(HEX_PATTERN);
  if (!matches) return text;

  let expanded = text;
  for (const match of matches) {
    try {
      const decoded = Buffer.from(match, 'hex').toString('utf-8');
      if (/^[\x20-\x7E\s]{4,}$/.test(decoded)) {
        expanded += ' ' + decoded;
      }
    } catch {
      // Not valid hex
    }
  }
  return expanded;
}

// ─── Main normalize function ────────────────────────────────────

export interface NormalizeOptions {
  /** Strip zero-width / invisible characters (default: true) */
  stripZeroWidth?: boolean;
  /** Replace homoglyphs with ASCII equivalents (default: true) */
  normalizeHomoglyphs?: boolean;
  /** Expand leetspeak to letters (default: true) */
  normalizeLeetspeak?: boolean;
  /** Decode HTML entities (default: true) */
  decodeHtml?: boolean;
  /** Decode URL encoding (default: true) */
  decodeUrl?: boolean;
  /** Detect and append decoded base64/hex payloads (default: true) */
  expandEncoded?: boolean;
  /** Apply Unicode NFKC normalization (default: true) */
  unicodeNormalize?: boolean;
}

/**
 * Normalize text to defeat evasion techniques.
 * Returns both the normalized text (for scanning) and the original (for redaction).
 *
 * The scanner runs patterns against the normalized version.
 */
export function normalizeText(text: string, options: NormalizeOptions = {}): string {
  const {
    stripZeroWidth = true,
    normalizeHomoglyphs = true,
    normalizeLeetspeak = true,
    decodeHtml = true,
    decodeUrl = true,
    expandEncoded = true,
    unicodeNormalize = true,
  } = options;

  let result = text;

  // 1. Unicode NFKC normalization (converts full-width, ligatures, etc.)
  if (unicodeNormalize) {
    result = result.normalize('NFKC');
    // Strip diacritics/accents: decompose to NFD, then remove combining marks
    result = result.normalize('NFD').replace(/[\u0300-\u036f]/g, '').normalize('NFC');
  }

  // 2. Strip zero-width / invisible characters
  if (stripZeroWidth) {
    result = result.replace(ZERO_WIDTH_CHARS, '');
  }

  // 3. Replace homoglyphs (Cyrillic/Greek → Latin)
  if (normalizeHomoglyphs) {
    result = Array.from(result)
      .map(ch => HOMOGLYPH_MAP[ch] ?? ch)
      .join('');
  }

  // 4. Decode HTML entities
  if (decodeHtml) {
    result = decodeHtmlEntities(result);
  }

  // 5. Decode URL encoding
  if (decodeUrl) {
    result = decodeUrlEncoding(result);
  }

  // 6. Expand base64 / hex payloads (append decoded version)
  if (expandEncoded) {
    result = expandBase64(result);
    result = expandHex(result);
  }

  // 7. Normalize leetspeak (run AFTER other normalizations)
  //    We produce a second "leet-normalized" copy and append it,
  //    so the original text still matches non-leet patterns.
  if (normalizeLeetspeak) {
    const leetNormalized = Array.from(result)
      .map(ch => LEET_MAP[ch] ?? ch)
      .join('');
    // Only append if it's different (avoids doubling clean text)
    if (leetNormalized !== result) {
      result = result + ' ' + leetNormalized;
    }
  }

  return result;
}

/**
 * Quick check: does text contain potential evasion indicators?
 * Used to skip expensive normalization on obviously clean text.
 */
export function hasEvasionIndicators(text: string): boolean {
  // Zero-width chars
  if (ZERO_WIDTH_CHARS.test(text)) return true;
  // Non-ASCII that could be homoglyphs (Cyrillic, Greek, full-width)
  if (/[\u0400-\u04FF\u0370-\u03FF\uFF00-\uFFEF]/.test(text)) return true;
  // Accented/diacritical Latin characters (could be evasion)
  if (/[\u00C0-\u024F]/.test(text)) return true;
  // Leetspeak digits in word context
  if (/[a-zA-Z][0-9@$!|][a-zA-Z]/.test(text)) return true;
  // HTML entities
  if (/&(?:#\d+|#x[0-9a-f]+|[a-z]+);/i.test(text)) return true;
  // URL encoding
  if (/%[0-9a-fA-F]{2}/.test(text)) return true;
  // Base64 blocks (16+ chars of base64 alphabet)
  if (/(?:[A-Za-z0-9+/]{4}){4,}/.test(text)) return true;
  return false;
}
