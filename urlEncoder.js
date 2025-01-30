/**
 * Classe utilitaire pour l'encodage et le décodage d'URLs
 */
class UrlEncoder {
  /**
   * Encode une chaîne de caractères pour une utilisation dans une URL
   * @param {string} str - La chaîne à encoder
   * @returns {string} La chaîne encodée
   */
  static encode(str) {
    if (typeof str !== "string") {
      throw new TypeError("L'argument doit être une chaîne de caractères");
    }

    return encodeURIComponent(str)
      .replace(
        /[!'()*]/g,
        (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`
      )
      .replace(/%(2[346B]|3[AC-F]|40|5[BDE]|60|7[BCD])/g, decodeURIComponent);
  }

  /**
   * Nettoie une chaîne de caractères des potentielles injections SQL
   * @param {string} str - La chaîne à nettoyer
   * @returns {string} La chaîne nettoyée
   * @private
   */
  static _sanitizeSQLInjection(str) {
    if (typeof str !== "string") return str;

    // Liste des motifs SQL dangereux
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|WHERE|FROM)\b)/gi,
      /'(''|[^'])*'/g,
      /;/g,
      /--/g,
      /\/\*/g,
      /\*\//g,
      /xp_/g,
    ];

    // On echappe les caractères spéciaux SQL
    let sanitized = str.replace(/[\0\x08\x09\x1a\n\r"'\\\%]/g, (char) => {
      switch (char) {
        case "\0":
          return "\\0";
        case "\x08":
          return "\\b";
        case "\x09":
          return "\\t";
        case "\x1a":
          return "\\z";
        case "\n":
          return "\\n";
        case "\r":
          return "\\r";
        case '"':
        case "'":
        case "\\":
          return "\\" + char;
        case "%":
          return "\\%";
      }
      return char;
    });

    // détecter et logger les tentatives d'injection
    const potentialInjection = sqlPatterns.some((pattern) => pattern.test(str));
    if (potentialInjection) {
      console.warn(`Tentative potentielle d'injection SQL détectée: ${str}`);
    }

    return sanitized;
  }

  /**
   * Décode une chaîne de caractères encodée pour URL avec protection contre les injections
   * @param {string} str - La chaîne encodée à décoder
   * @returns {string} La chaîne décodée et sécurisée
   */
  static decode(str) {
    if (typeof str !== "string") {
      throw new TypeError("L'argument doit être une chaîne de caractères");
    }

    const decoded = decodeURIComponent(str);
    return this._sanitizeSQLInjection(decoded);
  }

  /**
   * Encode un objet en chaîne de requête URL
   * @param {Object} params - L'objet à encoder
   * @returns {string} La chaîne de requête encodée
   */
  static encodeQueryParams(params) {
    if (typeof params !== "object" || params === null) {
      throw new TypeError("L'argument doit être un objet");
    }

    return Object.entries(params)
      .map(([key, value]) => {
        if (Array.isArray(value)) {
          return value
            .map((item) => `${this.encode(key)}=${this.encode(String(item))}`)
            .join("&");
        }
        return `${this.encode(key)}=${this.encode(String(value))}`;
      })
      .join("&");
  }

  /**
   * Décode une chaîne de requête URL en objet avec protection contre les injections
   * @param {string} queryString - La chaîne de requête à décoder
   * @returns {Object} L'objet décodé et sécurisé
   */
  static decodeQueryParams(queryString) {
    if (typeof queryString !== "string") {
      throw new TypeError("L'argument doit être une chaîne de caractères");
    }

    const params = {};

    const query = queryString.startsWith("?")
      ? queryString.slice(1)
      : queryString;

    if (!query) return params;

    query.split("&").forEach((param) => {
      const [key, value] = param.split("=");
      const decodedKey = this.decode(key);
      const decodedValue = value ? this.decode(value) : "";

      // Protection supplémentaire pour les valeurs
      const sanitizedValue = this._sanitizeSQLInjection(decodedValue);

      if (params[decodedKey]) {
        if (!Array.isArray(params[decodedKey])) {
          params[decodedKey] = [params[decodedKey]];
        }
        params[decodedKey].push(sanitizedValue);
      } else {
        params[decodedKey] = sanitizedValue;
      }
    });

    return params;
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = UrlEncoder;
}
