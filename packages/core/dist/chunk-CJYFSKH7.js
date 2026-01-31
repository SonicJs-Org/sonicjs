import { PluginBuilder, manifest_default, TurnstileService } from './chunk-J5WGMRSU.js';
import { HOOKS } from './chunk-LOUJRBXV.js';
import { __commonJS, __toESM } from './chunk-V4OQ3NZ2.js';
import { z } from 'zod';
import { Hono } from 'hono';

// ../../node_modules/semver/internal/constants.js
var require_constants = __commonJS({
  "../../node_modules/semver/internal/constants.js"(exports, module) {
    var SEMVER_SPEC_VERSION = "2.0.0";
    var MAX_LENGTH = 256;
    var MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER || /* istanbul ignore next */
    9007199254740991;
    var MAX_SAFE_COMPONENT_LENGTH = 16;
    var MAX_SAFE_BUILD_LENGTH = MAX_LENGTH - 6;
    var RELEASE_TYPES = [
      "major",
      "premajor",
      "minor",
      "preminor",
      "patch",
      "prepatch",
      "prerelease"
    ];
    module.exports = {
      MAX_LENGTH,
      MAX_SAFE_COMPONENT_LENGTH,
      MAX_SAFE_BUILD_LENGTH,
      MAX_SAFE_INTEGER,
      RELEASE_TYPES,
      SEMVER_SPEC_VERSION,
      FLAG_INCLUDE_PRERELEASE: 1,
      FLAG_LOOSE: 2
    };
  }
});

// ../../node_modules/semver/internal/debug.js
var require_debug = __commonJS({
  "../../node_modules/semver/internal/debug.js"(exports, module) {
    var debug = typeof process === "object" && process.env && process.env.NODE_DEBUG && /\bsemver\b/i.test(process.env.NODE_DEBUG) ? (...args) => console.error("SEMVER", ...args) : () => {
    };
    module.exports = debug;
  }
});

// ../../node_modules/semver/internal/re.js
var require_re = __commonJS({
  "../../node_modules/semver/internal/re.js"(exports, module) {
    var {
      MAX_SAFE_COMPONENT_LENGTH,
      MAX_SAFE_BUILD_LENGTH,
      MAX_LENGTH
    } = require_constants();
    var debug = require_debug();
    exports = module.exports = {};
    var re = exports.re = [];
    var safeRe = exports.safeRe = [];
    var src = exports.src = [];
    var safeSrc = exports.safeSrc = [];
    var t = exports.t = {};
    var R = 0;
    var LETTERDASHNUMBER = "[a-zA-Z0-9-]";
    var safeRegexReplacements = [
      ["\\s", 1],
      ["\\d", MAX_LENGTH],
      [LETTERDASHNUMBER, MAX_SAFE_BUILD_LENGTH]
    ];
    var makeSafeRegex = (value) => {
      for (const [token, max] of safeRegexReplacements) {
        value = value.split(`${token}*`).join(`${token}{0,${max}}`).split(`${token}+`).join(`${token}{1,${max}}`);
      }
      return value;
    };
    var createToken = (name, value, isGlobal) => {
      const safe = makeSafeRegex(value);
      const index = R++;
      debug(name, index, value);
      t[name] = index;
      src[index] = value;
      safeSrc[index] = safe;
      re[index] = new RegExp(value, isGlobal ? "g" : void 0);
      safeRe[index] = new RegExp(safe, isGlobal ? "g" : void 0);
    };
    createToken("NUMERICIDENTIFIER", "0|[1-9]\\d*");
    createToken("NUMERICIDENTIFIERLOOSE", "\\d+");
    createToken("NONNUMERICIDENTIFIER", `\\d*[a-zA-Z-]${LETTERDASHNUMBER}*`);
    createToken("MAINVERSION", `(${src[t.NUMERICIDENTIFIER]})\\.(${src[t.NUMERICIDENTIFIER]})\\.(${src[t.NUMERICIDENTIFIER]})`);
    createToken("MAINVERSIONLOOSE", `(${src[t.NUMERICIDENTIFIERLOOSE]})\\.(${src[t.NUMERICIDENTIFIERLOOSE]})\\.(${src[t.NUMERICIDENTIFIERLOOSE]})`);
    createToken("PRERELEASEIDENTIFIER", `(?:${src[t.NONNUMERICIDENTIFIER]}|${src[t.NUMERICIDENTIFIER]})`);
    createToken("PRERELEASEIDENTIFIERLOOSE", `(?:${src[t.NONNUMERICIDENTIFIER]}|${src[t.NUMERICIDENTIFIERLOOSE]})`);
    createToken("PRERELEASE", `(?:-(${src[t.PRERELEASEIDENTIFIER]}(?:\\.${src[t.PRERELEASEIDENTIFIER]})*))`);
    createToken("PRERELEASELOOSE", `(?:-?(${src[t.PRERELEASEIDENTIFIERLOOSE]}(?:\\.${src[t.PRERELEASEIDENTIFIERLOOSE]})*))`);
    createToken("BUILDIDENTIFIER", `${LETTERDASHNUMBER}+`);
    createToken("BUILD", `(?:\\+(${src[t.BUILDIDENTIFIER]}(?:\\.${src[t.BUILDIDENTIFIER]})*))`);
    createToken("FULLPLAIN", `v?${src[t.MAINVERSION]}${src[t.PRERELEASE]}?${src[t.BUILD]}?`);
    createToken("FULL", `^${src[t.FULLPLAIN]}$`);
    createToken("LOOSEPLAIN", `[v=\\s]*${src[t.MAINVERSIONLOOSE]}${src[t.PRERELEASELOOSE]}?${src[t.BUILD]}?`);
    createToken("LOOSE", `^${src[t.LOOSEPLAIN]}$`);
    createToken("GTLT", "((?:<|>)?=?)");
    createToken("XRANGEIDENTIFIERLOOSE", `${src[t.NUMERICIDENTIFIERLOOSE]}|x|X|\\*`);
    createToken("XRANGEIDENTIFIER", `${src[t.NUMERICIDENTIFIER]}|x|X|\\*`);
    createToken("XRANGEPLAIN", `[v=\\s]*(${src[t.XRANGEIDENTIFIER]})(?:\\.(${src[t.XRANGEIDENTIFIER]})(?:\\.(${src[t.XRANGEIDENTIFIER]})(?:${src[t.PRERELEASE]})?${src[t.BUILD]}?)?)?`);
    createToken("XRANGEPLAINLOOSE", `[v=\\s]*(${src[t.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t.XRANGEIDENTIFIERLOOSE]})(?:${src[t.PRERELEASELOOSE]})?${src[t.BUILD]}?)?)?`);
    createToken("XRANGE", `^${src[t.GTLT]}\\s*${src[t.XRANGEPLAIN]}$`);
    createToken("XRANGELOOSE", `^${src[t.GTLT]}\\s*${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("COERCEPLAIN", `${"(^|[^\\d])(\\d{1,"}${MAX_SAFE_COMPONENT_LENGTH}})(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}}))?(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}}))?`);
    createToken("COERCE", `${src[t.COERCEPLAIN]}(?:$|[^\\d])`);
    createToken("COERCEFULL", src[t.COERCEPLAIN] + `(?:${src[t.PRERELEASE]})?(?:${src[t.BUILD]})?(?:$|[^\\d])`);
    createToken("COERCERTL", src[t.COERCE], true);
    createToken("COERCERTLFULL", src[t.COERCEFULL], true);
    createToken("LONETILDE", "(?:~>?)");
    createToken("TILDETRIM", `(\\s*)${src[t.LONETILDE]}\\s+`, true);
    exports.tildeTrimReplace = "$1~";
    createToken("TILDE", `^${src[t.LONETILDE]}${src[t.XRANGEPLAIN]}$`);
    createToken("TILDELOOSE", `^${src[t.LONETILDE]}${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("LONECARET", "(?:\\^)");
    createToken("CARETTRIM", `(\\s*)${src[t.LONECARET]}\\s+`, true);
    exports.caretTrimReplace = "$1^";
    createToken("CARET", `^${src[t.LONECARET]}${src[t.XRANGEPLAIN]}$`);
    createToken("CARETLOOSE", `^${src[t.LONECARET]}${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("COMPARATORLOOSE", `^${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]})$|^$`);
    createToken("COMPARATOR", `^${src[t.GTLT]}\\s*(${src[t.FULLPLAIN]})$|^$`);
    createToken("COMPARATORTRIM", `(\\s*)${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]}|${src[t.XRANGEPLAIN]})`, true);
    exports.comparatorTrimReplace = "$1$2$3";
    createToken("HYPHENRANGE", `^\\s*(${src[t.XRANGEPLAIN]})\\s+-\\s+(${src[t.XRANGEPLAIN]})\\s*$`);
    createToken("HYPHENRANGELOOSE", `^\\s*(${src[t.XRANGEPLAINLOOSE]})\\s+-\\s+(${src[t.XRANGEPLAINLOOSE]})\\s*$`);
    createToken("STAR", "(<|>)?=?\\s*\\*");
    createToken("GTE0", "^\\s*>=\\s*0\\.0\\.0\\s*$");
    createToken("GTE0PRE", "^\\s*>=\\s*0\\.0\\.0-0\\s*$");
  }
});

// ../../node_modules/semver/internal/parse-options.js
var require_parse_options = __commonJS({
  "../../node_modules/semver/internal/parse-options.js"(exports, module) {
    var looseOption = Object.freeze({ loose: true });
    var emptyOpts = Object.freeze({});
    var parseOptions = (options) => {
      if (!options) {
        return emptyOpts;
      }
      if (typeof options !== "object") {
        return looseOption;
      }
      return options;
    };
    module.exports = parseOptions;
  }
});

// ../../node_modules/semver/internal/identifiers.js
var require_identifiers = __commonJS({
  "../../node_modules/semver/internal/identifiers.js"(exports, module) {
    var numeric = /^[0-9]+$/;
    var compareIdentifiers = (a, b) => {
      if (typeof a === "number" && typeof b === "number") {
        return a === b ? 0 : a < b ? -1 : 1;
      }
      const anum = numeric.test(a);
      const bnum = numeric.test(b);
      if (anum && bnum) {
        a = +a;
        b = +b;
      }
      return a === b ? 0 : anum && !bnum ? -1 : bnum && !anum ? 1 : a < b ? -1 : 1;
    };
    var rcompareIdentifiers = (a, b) => compareIdentifiers(b, a);
    module.exports = {
      compareIdentifiers,
      rcompareIdentifiers
    };
  }
});

// ../../node_modules/semver/classes/semver.js
var require_semver = __commonJS({
  "../../node_modules/semver/classes/semver.js"(exports, module) {
    var debug = require_debug();
    var { MAX_LENGTH, MAX_SAFE_INTEGER } = require_constants();
    var { safeRe: re, t } = require_re();
    var parseOptions = require_parse_options();
    var { compareIdentifiers } = require_identifiers();
    var SemVer = class _SemVer {
      constructor(version, options) {
        options = parseOptions(options);
        if (version instanceof _SemVer) {
          if (version.loose === !!options.loose && version.includePrerelease === !!options.includePrerelease) {
            return version;
          } else {
            version = version.version;
          }
        } else if (typeof version !== "string") {
          throw new TypeError(`Invalid version. Must be a string. Got type "${typeof version}".`);
        }
        if (version.length > MAX_LENGTH) {
          throw new TypeError(
            `version is longer than ${MAX_LENGTH} characters`
          );
        }
        debug("SemVer", version, options);
        this.options = options;
        this.loose = !!options.loose;
        this.includePrerelease = !!options.includePrerelease;
        const m = version.trim().match(options.loose ? re[t.LOOSE] : re[t.FULL]);
        if (!m) {
          throw new TypeError(`Invalid Version: ${version}`);
        }
        this.raw = version;
        this.major = +m[1];
        this.minor = +m[2];
        this.patch = +m[3];
        if (this.major > MAX_SAFE_INTEGER || this.major < 0) {
          throw new TypeError("Invalid major version");
        }
        if (this.minor > MAX_SAFE_INTEGER || this.minor < 0) {
          throw new TypeError("Invalid minor version");
        }
        if (this.patch > MAX_SAFE_INTEGER || this.patch < 0) {
          throw new TypeError("Invalid patch version");
        }
        if (!m[4]) {
          this.prerelease = [];
        } else {
          this.prerelease = m[4].split(".").map((id) => {
            if (/^[0-9]+$/.test(id)) {
              const num = +id;
              if (num >= 0 && num < MAX_SAFE_INTEGER) {
                return num;
              }
            }
            return id;
          });
        }
        this.build = m[5] ? m[5].split(".") : [];
        this.format();
      }
      format() {
        this.version = `${this.major}.${this.minor}.${this.patch}`;
        if (this.prerelease.length) {
          this.version += `-${this.prerelease.join(".")}`;
        }
        return this.version;
      }
      toString() {
        return this.version;
      }
      compare(other) {
        debug("SemVer.compare", this.version, this.options, other);
        if (!(other instanceof _SemVer)) {
          if (typeof other === "string" && other === this.version) {
            return 0;
          }
          other = new _SemVer(other, this.options);
        }
        if (other.version === this.version) {
          return 0;
        }
        return this.compareMain(other) || this.comparePre(other);
      }
      compareMain(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        if (this.major < other.major) {
          return -1;
        }
        if (this.major > other.major) {
          return 1;
        }
        if (this.minor < other.minor) {
          return -1;
        }
        if (this.minor > other.minor) {
          return 1;
        }
        if (this.patch < other.patch) {
          return -1;
        }
        if (this.patch > other.patch) {
          return 1;
        }
        return 0;
      }
      comparePre(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        if (this.prerelease.length && !other.prerelease.length) {
          return -1;
        } else if (!this.prerelease.length && other.prerelease.length) {
          return 1;
        } else if (!this.prerelease.length && !other.prerelease.length) {
          return 0;
        }
        let i = 0;
        do {
          const a = this.prerelease[i];
          const b = other.prerelease[i];
          debug("prerelease compare", i, a, b);
          if (a === void 0 && b === void 0) {
            return 0;
          } else if (b === void 0) {
            return 1;
          } else if (a === void 0) {
            return -1;
          } else if (a === b) {
            continue;
          } else {
            return compareIdentifiers(a, b);
          }
        } while (++i);
      }
      compareBuild(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        let i = 0;
        do {
          const a = this.build[i];
          const b = other.build[i];
          debug("build compare", i, a, b);
          if (a === void 0 && b === void 0) {
            return 0;
          } else if (b === void 0) {
            return 1;
          } else if (a === void 0) {
            return -1;
          } else if (a === b) {
            continue;
          } else {
            return compareIdentifiers(a, b);
          }
        } while (++i);
      }
      // preminor will bump the version up to the next minor release, and immediately
      // down to pre-release. premajor and prepatch work the same way.
      inc(release, identifier, identifierBase) {
        if (release.startsWith("pre")) {
          if (!identifier && identifierBase === false) {
            throw new Error("invalid increment argument: identifier is empty");
          }
          if (identifier) {
            const match = `-${identifier}`.match(this.options.loose ? re[t.PRERELEASELOOSE] : re[t.PRERELEASE]);
            if (!match || match[1] !== identifier) {
              throw new Error(`invalid identifier: ${identifier}`);
            }
          }
        }
        switch (release) {
          case "premajor":
            this.prerelease.length = 0;
            this.patch = 0;
            this.minor = 0;
            this.major++;
            this.inc("pre", identifier, identifierBase);
            break;
          case "preminor":
            this.prerelease.length = 0;
            this.patch = 0;
            this.minor++;
            this.inc("pre", identifier, identifierBase);
            break;
          case "prepatch":
            this.prerelease.length = 0;
            this.inc("patch", identifier, identifierBase);
            this.inc("pre", identifier, identifierBase);
            break;
          // If the input is a non-prerelease version, this acts the same as
          // prepatch.
          case "prerelease":
            if (this.prerelease.length === 0) {
              this.inc("patch", identifier, identifierBase);
            }
            this.inc("pre", identifier, identifierBase);
            break;
          case "release":
            if (this.prerelease.length === 0) {
              throw new Error(`version ${this.raw} is not a prerelease`);
            }
            this.prerelease.length = 0;
            break;
          case "major":
            if (this.minor !== 0 || this.patch !== 0 || this.prerelease.length === 0) {
              this.major++;
            }
            this.minor = 0;
            this.patch = 0;
            this.prerelease = [];
            break;
          case "minor":
            if (this.patch !== 0 || this.prerelease.length === 0) {
              this.minor++;
            }
            this.patch = 0;
            this.prerelease = [];
            break;
          case "patch":
            if (this.prerelease.length === 0) {
              this.patch++;
            }
            this.prerelease = [];
            break;
          // This probably shouldn't be used publicly.
          // 1.0.0 'pre' would become 1.0.0-0 which is the wrong direction.
          case "pre": {
            const base = Number(identifierBase) ? 1 : 0;
            if (this.prerelease.length === 0) {
              this.prerelease = [base];
            } else {
              let i = this.prerelease.length;
              while (--i >= 0) {
                if (typeof this.prerelease[i] === "number") {
                  this.prerelease[i]++;
                  i = -2;
                }
              }
              if (i === -1) {
                if (identifier === this.prerelease.join(".") && identifierBase === false) {
                  throw new Error("invalid increment argument: identifier already exists");
                }
                this.prerelease.push(base);
              }
            }
            if (identifier) {
              let prerelease = [identifier, base];
              if (identifierBase === false) {
                prerelease = [identifier];
              }
              if (compareIdentifiers(this.prerelease[0], identifier) === 0) {
                if (isNaN(this.prerelease[1])) {
                  this.prerelease = prerelease;
                }
              } else {
                this.prerelease = prerelease;
              }
            }
            break;
          }
          default:
            throw new Error(`invalid increment argument: ${release}`);
        }
        this.raw = this.format();
        if (this.build.length) {
          this.raw += `+${this.build.join(".")}`;
        }
        return this;
      }
    };
    module.exports = SemVer;
  }
});

// ../../node_modules/semver/functions/parse.js
var require_parse = __commonJS({
  "../../node_modules/semver/functions/parse.js"(exports, module) {
    var SemVer = require_semver();
    var parse = (version, options, throwErrors = false) => {
      if (version instanceof SemVer) {
        return version;
      }
      try {
        return new SemVer(version, options);
      } catch (er) {
        if (!throwErrors) {
          return null;
        }
        throw er;
      }
    };
    module.exports = parse;
  }
});

// ../../node_modules/semver/functions/valid.js
var require_valid = __commonJS({
  "../../node_modules/semver/functions/valid.js"(exports, module) {
    var parse = require_parse();
    var valid = (version, options) => {
      const v = parse(version, options);
      return v ? v.version : null;
    };
    module.exports = valid;
  }
});

// ../../node_modules/semver/functions/clean.js
var require_clean = __commonJS({
  "../../node_modules/semver/functions/clean.js"(exports, module) {
    var parse = require_parse();
    var clean = (version, options) => {
      const s = parse(version.trim().replace(/^[=v]+/, ""), options);
      return s ? s.version : null;
    };
    module.exports = clean;
  }
});

// ../../node_modules/semver/functions/inc.js
var require_inc = __commonJS({
  "../../node_modules/semver/functions/inc.js"(exports, module) {
    var SemVer = require_semver();
    var inc = (version, release, options, identifier, identifierBase) => {
      if (typeof options === "string") {
        identifierBase = identifier;
        identifier = options;
        options = void 0;
      }
      try {
        return new SemVer(
          version instanceof SemVer ? version.version : version,
          options
        ).inc(release, identifier, identifierBase).version;
      } catch (er) {
        return null;
      }
    };
    module.exports = inc;
  }
});

// ../../node_modules/semver/functions/diff.js
var require_diff = __commonJS({
  "../../node_modules/semver/functions/diff.js"(exports, module) {
    var parse = require_parse();
    var diff = (version1, version2) => {
      const v1 = parse(version1, null, true);
      const v2 = parse(version2, null, true);
      const comparison = v1.compare(v2);
      if (comparison === 0) {
        return null;
      }
      const v1Higher = comparison > 0;
      const highVersion = v1Higher ? v1 : v2;
      const lowVersion = v1Higher ? v2 : v1;
      const highHasPre = !!highVersion.prerelease.length;
      const lowHasPre = !!lowVersion.prerelease.length;
      if (lowHasPre && !highHasPre) {
        if (!lowVersion.patch && !lowVersion.minor) {
          return "major";
        }
        if (lowVersion.compareMain(highVersion) === 0) {
          if (lowVersion.minor && !lowVersion.patch) {
            return "minor";
          }
          return "patch";
        }
      }
      const prefix = highHasPre ? "pre" : "";
      if (v1.major !== v2.major) {
        return prefix + "major";
      }
      if (v1.minor !== v2.minor) {
        return prefix + "minor";
      }
      if (v1.patch !== v2.patch) {
        return prefix + "patch";
      }
      return "prerelease";
    };
    module.exports = diff;
  }
});

// ../../node_modules/semver/functions/major.js
var require_major = __commonJS({
  "../../node_modules/semver/functions/major.js"(exports, module) {
    var SemVer = require_semver();
    var major = (a, loose) => new SemVer(a, loose).major;
    module.exports = major;
  }
});

// ../../node_modules/semver/functions/minor.js
var require_minor = __commonJS({
  "../../node_modules/semver/functions/minor.js"(exports, module) {
    var SemVer = require_semver();
    var minor = (a, loose) => new SemVer(a, loose).minor;
    module.exports = minor;
  }
});

// ../../node_modules/semver/functions/patch.js
var require_patch = __commonJS({
  "../../node_modules/semver/functions/patch.js"(exports, module) {
    var SemVer = require_semver();
    var patch = (a, loose) => new SemVer(a, loose).patch;
    module.exports = patch;
  }
});

// ../../node_modules/semver/functions/prerelease.js
var require_prerelease = __commonJS({
  "../../node_modules/semver/functions/prerelease.js"(exports, module) {
    var parse = require_parse();
    var prerelease = (version, options) => {
      const parsed = parse(version, options);
      return parsed && parsed.prerelease.length ? parsed.prerelease : null;
    };
    module.exports = prerelease;
  }
});

// ../../node_modules/semver/functions/compare.js
var require_compare = __commonJS({
  "../../node_modules/semver/functions/compare.js"(exports, module) {
    var SemVer = require_semver();
    var compare = (a, b, loose) => new SemVer(a, loose).compare(new SemVer(b, loose));
    module.exports = compare;
  }
});

// ../../node_modules/semver/functions/rcompare.js
var require_rcompare = __commonJS({
  "../../node_modules/semver/functions/rcompare.js"(exports, module) {
    var compare = require_compare();
    var rcompare = (a, b, loose) => compare(b, a, loose);
    module.exports = rcompare;
  }
});

// ../../node_modules/semver/functions/compare-loose.js
var require_compare_loose = __commonJS({
  "../../node_modules/semver/functions/compare-loose.js"(exports, module) {
    var compare = require_compare();
    var compareLoose = (a, b) => compare(a, b, true);
    module.exports = compareLoose;
  }
});

// ../../node_modules/semver/functions/compare-build.js
var require_compare_build = __commonJS({
  "../../node_modules/semver/functions/compare-build.js"(exports, module) {
    var SemVer = require_semver();
    var compareBuild = (a, b, loose) => {
      const versionA = new SemVer(a, loose);
      const versionB = new SemVer(b, loose);
      return versionA.compare(versionB) || versionA.compareBuild(versionB);
    };
    module.exports = compareBuild;
  }
});

// ../../node_modules/semver/functions/sort.js
var require_sort = __commonJS({
  "../../node_modules/semver/functions/sort.js"(exports, module) {
    var compareBuild = require_compare_build();
    var sort = (list, loose) => list.sort((a, b) => compareBuild(a, b, loose));
    module.exports = sort;
  }
});

// ../../node_modules/semver/functions/rsort.js
var require_rsort = __commonJS({
  "../../node_modules/semver/functions/rsort.js"(exports, module) {
    var compareBuild = require_compare_build();
    var rsort = (list, loose) => list.sort((a, b) => compareBuild(b, a, loose));
    module.exports = rsort;
  }
});

// ../../node_modules/semver/functions/gt.js
var require_gt = __commonJS({
  "../../node_modules/semver/functions/gt.js"(exports, module) {
    var compare = require_compare();
    var gt = (a, b, loose) => compare(a, b, loose) > 0;
    module.exports = gt;
  }
});

// ../../node_modules/semver/functions/lt.js
var require_lt = __commonJS({
  "../../node_modules/semver/functions/lt.js"(exports, module) {
    var compare = require_compare();
    var lt = (a, b, loose) => compare(a, b, loose) < 0;
    module.exports = lt;
  }
});

// ../../node_modules/semver/functions/eq.js
var require_eq = __commonJS({
  "../../node_modules/semver/functions/eq.js"(exports, module) {
    var compare = require_compare();
    var eq = (a, b, loose) => compare(a, b, loose) === 0;
    module.exports = eq;
  }
});

// ../../node_modules/semver/functions/neq.js
var require_neq = __commonJS({
  "../../node_modules/semver/functions/neq.js"(exports, module) {
    var compare = require_compare();
    var neq = (a, b, loose) => compare(a, b, loose) !== 0;
    module.exports = neq;
  }
});

// ../../node_modules/semver/functions/gte.js
var require_gte = __commonJS({
  "../../node_modules/semver/functions/gte.js"(exports, module) {
    var compare = require_compare();
    var gte = (a, b, loose) => compare(a, b, loose) >= 0;
    module.exports = gte;
  }
});

// ../../node_modules/semver/functions/lte.js
var require_lte = __commonJS({
  "../../node_modules/semver/functions/lte.js"(exports, module) {
    var compare = require_compare();
    var lte = (a, b, loose) => compare(a, b, loose) <= 0;
    module.exports = lte;
  }
});

// ../../node_modules/semver/functions/cmp.js
var require_cmp = __commonJS({
  "../../node_modules/semver/functions/cmp.js"(exports, module) {
    var eq = require_eq();
    var neq = require_neq();
    var gt = require_gt();
    var gte = require_gte();
    var lt = require_lt();
    var lte = require_lte();
    var cmp = (a, op, b, loose) => {
      switch (op) {
        case "===":
          if (typeof a === "object") {
            a = a.version;
          }
          if (typeof b === "object") {
            b = b.version;
          }
          return a === b;
        case "!==":
          if (typeof a === "object") {
            a = a.version;
          }
          if (typeof b === "object") {
            b = b.version;
          }
          return a !== b;
        case "":
        case "=":
        case "==":
          return eq(a, b, loose);
        case "!=":
          return neq(a, b, loose);
        case ">":
          return gt(a, b, loose);
        case ">=":
          return gte(a, b, loose);
        case "<":
          return lt(a, b, loose);
        case "<=":
          return lte(a, b, loose);
        default:
          throw new TypeError(`Invalid operator: ${op}`);
      }
    };
    module.exports = cmp;
  }
});

// ../../node_modules/semver/functions/coerce.js
var require_coerce = __commonJS({
  "../../node_modules/semver/functions/coerce.js"(exports, module) {
    var SemVer = require_semver();
    var parse = require_parse();
    var { safeRe: re, t } = require_re();
    var coerce = (version, options) => {
      if (version instanceof SemVer) {
        return version;
      }
      if (typeof version === "number") {
        version = String(version);
      }
      if (typeof version !== "string") {
        return null;
      }
      options = options || {};
      let match = null;
      if (!options.rtl) {
        match = version.match(options.includePrerelease ? re[t.COERCEFULL] : re[t.COERCE]);
      } else {
        const coerceRtlRegex = options.includePrerelease ? re[t.COERCERTLFULL] : re[t.COERCERTL];
        let next;
        while ((next = coerceRtlRegex.exec(version)) && (!match || match.index + match[0].length !== version.length)) {
          if (!match || next.index + next[0].length !== match.index + match[0].length) {
            match = next;
          }
          coerceRtlRegex.lastIndex = next.index + next[1].length + next[2].length;
        }
        coerceRtlRegex.lastIndex = -1;
      }
      if (match === null) {
        return null;
      }
      const major = match[2];
      const minor = match[3] || "0";
      const patch = match[4] || "0";
      const prerelease = options.includePrerelease && match[5] ? `-${match[5]}` : "";
      const build = options.includePrerelease && match[6] ? `+${match[6]}` : "";
      return parse(`${major}.${minor}.${patch}${prerelease}${build}`, options);
    };
    module.exports = coerce;
  }
});

// ../../node_modules/semver/internal/lrucache.js
var require_lrucache = __commonJS({
  "../../node_modules/semver/internal/lrucache.js"(exports, module) {
    var LRUCache = class {
      constructor() {
        this.max = 1e3;
        this.map = /* @__PURE__ */ new Map();
      }
      get(key) {
        const value = this.map.get(key);
        if (value === void 0) {
          return void 0;
        } else {
          this.map.delete(key);
          this.map.set(key, value);
          return value;
        }
      }
      delete(key) {
        return this.map.delete(key);
      }
      set(key, value) {
        const deleted = this.delete(key);
        if (!deleted && value !== void 0) {
          if (this.map.size >= this.max) {
            const firstKey = this.map.keys().next().value;
            this.delete(firstKey);
          }
          this.map.set(key, value);
        }
        return this;
      }
    };
    module.exports = LRUCache;
  }
});

// ../../node_modules/semver/classes/range.js
var require_range = __commonJS({
  "../../node_modules/semver/classes/range.js"(exports, module) {
    var SPACE_CHARACTERS = /\s+/g;
    var Range = class _Range {
      constructor(range, options) {
        options = parseOptions(options);
        if (range instanceof _Range) {
          if (range.loose === !!options.loose && range.includePrerelease === !!options.includePrerelease) {
            return range;
          } else {
            return new _Range(range.raw, options);
          }
        }
        if (range instanceof Comparator) {
          this.raw = range.value;
          this.set = [[range]];
          this.formatted = void 0;
          return this;
        }
        this.options = options;
        this.loose = !!options.loose;
        this.includePrerelease = !!options.includePrerelease;
        this.raw = range.trim().replace(SPACE_CHARACTERS, " ");
        this.set = this.raw.split("||").map((r) => this.parseRange(r.trim())).filter((c) => c.length);
        if (!this.set.length) {
          throw new TypeError(`Invalid SemVer Range: ${this.raw}`);
        }
        if (this.set.length > 1) {
          const first = this.set[0];
          this.set = this.set.filter((c) => !isNullSet(c[0]));
          if (this.set.length === 0) {
            this.set = [first];
          } else if (this.set.length > 1) {
            for (const c of this.set) {
              if (c.length === 1 && isAny(c[0])) {
                this.set = [c];
                break;
              }
            }
          }
        }
        this.formatted = void 0;
      }
      get range() {
        if (this.formatted === void 0) {
          this.formatted = "";
          for (let i = 0; i < this.set.length; i++) {
            if (i > 0) {
              this.formatted += "||";
            }
            const comps = this.set[i];
            for (let k = 0; k < comps.length; k++) {
              if (k > 0) {
                this.formatted += " ";
              }
              this.formatted += comps[k].toString().trim();
            }
          }
        }
        return this.formatted;
      }
      format() {
        return this.range;
      }
      toString() {
        return this.range;
      }
      parseRange(range) {
        const memoOpts = (this.options.includePrerelease && FLAG_INCLUDE_PRERELEASE) | (this.options.loose && FLAG_LOOSE);
        const memoKey = memoOpts + ":" + range;
        const cached = cache.get(memoKey);
        if (cached) {
          return cached;
        }
        const loose = this.options.loose;
        const hr = loose ? re[t.HYPHENRANGELOOSE] : re[t.HYPHENRANGE];
        range = range.replace(hr, hyphenReplace(this.options.includePrerelease));
        debug("hyphen replace", range);
        range = range.replace(re[t.COMPARATORTRIM], comparatorTrimReplace);
        debug("comparator trim", range);
        range = range.replace(re[t.TILDETRIM], tildeTrimReplace);
        debug("tilde trim", range);
        range = range.replace(re[t.CARETTRIM], caretTrimReplace);
        debug("caret trim", range);
        let rangeList = range.split(" ").map((comp) => parseComparator(comp, this.options)).join(" ").split(/\s+/).map((comp) => replaceGTE0(comp, this.options));
        if (loose) {
          rangeList = rangeList.filter((comp) => {
            debug("loose invalid filter", comp, this.options);
            return !!comp.match(re[t.COMPARATORLOOSE]);
          });
        }
        debug("range list", rangeList);
        const rangeMap = /* @__PURE__ */ new Map();
        const comparators = rangeList.map((comp) => new Comparator(comp, this.options));
        for (const comp of comparators) {
          if (isNullSet(comp)) {
            return [comp];
          }
          rangeMap.set(comp.value, comp);
        }
        if (rangeMap.size > 1 && rangeMap.has("")) {
          rangeMap.delete("");
        }
        const result = [...rangeMap.values()];
        cache.set(memoKey, result);
        return result;
      }
      intersects(range, options) {
        if (!(range instanceof _Range)) {
          throw new TypeError("a Range is required");
        }
        return this.set.some((thisComparators) => {
          return isSatisfiable(thisComparators, options) && range.set.some((rangeComparators) => {
            return isSatisfiable(rangeComparators, options) && thisComparators.every((thisComparator) => {
              return rangeComparators.every((rangeComparator) => {
                return thisComparator.intersects(rangeComparator, options);
              });
            });
          });
        });
      }
      // if ANY of the sets match ALL of its comparators, then pass
      test(version) {
        if (!version) {
          return false;
        }
        if (typeof version === "string") {
          try {
            version = new SemVer(version, this.options);
          } catch (er) {
            return false;
          }
        }
        for (let i = 0; i < this.set.length; i++) {
          if (testSet(this.set[i], version, this.options)) {
            return true;
          }
        }
        return false;
      }
    };
    module.exports = Range;
    var LRU = require_lrucache();
    var cache = new LRU();
    var parseOptions = require_parse_options();
    var Comparator = require_comparator();
    var debug = require_debug();
    var SemVer = require_semver();
    var {
      safeRe: re,
      t,
      comparatorTrimReplace,
      tildeTrimReplace,
      caretTrimReplace
    } = require_re();
    var { FLAG_INCLUDE_PRERELEASE, FLAG_LOOSE } = require_constants();
    var isNullSet = (c) => c.value === "<0.0.0-0";
    var isAny = (c) => c.value === "";
    var isSatisfiable = (comparators, options) => {
      let result = true;
      const remainingComparators = comparators.slice();
      let testComparator = remainingComparators.pop();
      while (result && remainingComparators.length) {
        result = remainingComparators.every((otherComparator) => {
          return testComparator.intersects(otherComparator, options);
        });
        testComparator = remainingComparators.pop();
      }
      return result;
    };
    var parseComparator = (comp, options) => {
      comp = comp.replace(re[t.BUILD], "");
      debug("comp", comp, options);
      comp = replaceCarets(comp, options);
      debug("caret", comp);
      comp = replaceTildes(comp, options);
      debug("tildes", comp);
      comp = replaceXRanges(comp, options);
      debug("xrange", comp);
      comp = replaceStars(comp, options);
      debug("stars", comp);
      return comp;
    };
    var isX = (id) => !id || id.toLowerCase() === "x" || id === "*";
    var replaceTildes = (comp, options) => {
      return comp.trim().split(/\s+/).map((c) => replaceTilde(c, options)).join(" ");
    };
    var replaceTilde = (comp, options) => {
      const r = options.loose ? re[t.TILDELOOSE] : re[t.TILDE];
      return comp.replace(r, (_, M, m, p, pr) => {
        debug("tilde", comp, _, M, m, p, pr);
        let ret;
        if (isX(M)) {
          ret = "";
        } else if (isX(m)) {
          ret = `>=${M}.0.0 <${+M + 1}.0.0-0`;
        } else if (isX(p)) {
          ret = `>=${M}.${m}.0 <${M}.${+m + 1}.0-0`;
        } else if (pr) {
          debug("replaceTilde pr", pr);
          ret = `>=${M}.${m}.${p}-${pr} <${M}.${+m + 1}.0-0`;
        } else {
          ret = `>=${M}.${m}.${p} <${M}.${+m + 1}.0-0`;
        }
        debug("tilde return", ret);
        return ret;
      });
    };
    var replaceCarets = (comp, options) => {
      return comp.trim().split(/\s+/).map((c) => replaceCaret(c, options)).join(" ");
    };
    var replaceCaret = (comp, options) => {
      debug("caret", comp, options);
      const r = options.loose ? re[t.CARETLOOSE] : re[t.CARET];
      const z2 = options.includePrerelease ? "-0" : "";
      return comp.replace(r, (_, M, m, p, pr) => {
        debug("caret", comp, _, M, m, p, pr);
        let ret;
        if (isX(M)) {
          ret = "";
        } else if (isX(m)) {
          ret = `>=${M}.0.0${z2} <${+M + 1}.0.0-0`;
        } else if (isX(p)) {
          if (M === "0") {
            ret = `>=${M}.${m}.0${z2} <${M}.${+m + 1}.0-0`;
          } else {
            ret = `>=${M}.${m}.0${z2} <${+M + 1}.0.0-0`;
          }
        } else if (pr) {
          debug("replaceCaret pr", pr);
          if (M === "0") {
            if (m === "0") {
              ret = `>=${M}.${m}.${p}-${pr} <${M}.${m}.${+p + 1}-0`;
            } else {
              ret = `>=${M}.${m}.${p}-${pr} <${M}.${+m + 1}.0-0`;
            }
          } else {
            ret = `>=${M}.${m}.${p}-${pr} <${+M + 1}.0.0-0`;
          }
        } else {
          debug("no pr");
          if (M === "0") {
            if (m === "0") {
              ret = `>=${M}.${m}.${p}${z2} <${M}.${m}.${+p + 1}-0`;
            } else {
              ret = `>=${M}.${m}.${p}${z2} <${M}.${+m + 1}.0-0`;
            }
          } else {
            ret = `>=${M}.${m}.${p} <${+M + 1}.0.0-0`;
          }
        }
        debug("caret return", ret);
        return ret;
      });
    };
    var replaceXRanges = (comp, options) => {
      debug("replaceXRanges", comp, options);
      return comp.split(/\s+/).map((c) => replaceXRange(c, options)).join(" ");
    };
    var replaceXRange = (comp, options) => {
      comp = comp.trim();
      const r = options.loose ? re[t.XRANGELOOSE] : re[t.XRANGE];
      return comp.replace(r, (ret, gtlt, M, m, p, pr) => {
        debug("xRange", comp, ret, gtlt, M, m, p, pr);
        const xM = isX(M);
        const xm = xM || isX(m);
        const xp = xm || isX(p);
        const anyX = xp;
        if (gtlt === "=" && anyX) {
          gtlt = "";
        }
        pr = options.includePrerelease ? "-0" : "";
        if (xM) {
          if (gtlt === ">" || gtlt === "<") {
            ret = "<0.0.0-0";
          } else {
            ret = "*";
          }
        } else if (gtlt && anyX) {
          if (xm) {
            m = 0;
          }
          p = 0;
          if (gtlt === ">") {
            gtlt = ">=";
            if (xm) {
              M = +M + 1;
              m = 0;
              p = 0;
            } else {
              m = +m + 1;
              p = 0;
            }
          } else if (gtlt === "<=") {
            gtlt = "<";
            if (xm) {
              M = +M + 1;
            } else {
              m = +m + 1;
            }
          }
          if (gtlt === "<") {
            pr = "-0";
          }
          ret = `${gtlt + M}.${m}.${p}${pr}`;
        } else if (xm) {
          ret = `>=${M}.0.0${pr} <${+M + 1}.0.0-0`;
        } else if (xp) {
          ret = `>=${M}.${m}.0${pr} <${M}.${+m + 1}.0-0`;
        }
        debug("xRange return", ret);
        return ret;
      });
    };
    var replaceStars = (comp, options) => {
      debug("replaceStars", comp, options);
      return comp.trim().replace(re[t.STAR], "");
    };
    var replaceGTE0 = (comp, options) => {
      debug("replaceGTE0", comp, options);
      return comp.trim().replace(re[options.includePrerelease ? t.GTE0PRE : t.GTE0], "");
    };
    var hyphenReplace = (incPr) => ($0, from, fM, fm, fp, fpr, fb, to, tM, tm, tp, tpr) => {
      if (isX(fM)) {
        from = "";
      } else if (isX(fm)) {
        from = `>=${fM}.0.0${incPr ? "-0" : ""}`;
      } else if (isX(fp)) {
        from = `>=${fM}.${fm}.0${incPr ? "-0" : ""}`;
      } else if (fpr) {
        from = `>=${from}`;
      } else {
        from = `>=${from}${incPr ? "-0" : ""}`;
      }
      if (isX(tM)) {
        to = "";
      } else if (isX(tm)) {
        to = `<${+tM + 1}.0.0-0`;
      } else if (isX(tp)) {
        to = `<${tM}.${+tm + 1}.0-0`;
      } else if (tpr) {
        to = `<=${tM}.${tm}.${tp}-${tpr}`;
      } else if (incPr) {
        to = `<${tM}.${tm}.${+tp + 1}-0`;
      } else {
        to = `<=${to}`;
      }
      return `${from} ${to}`.trim();
    };
    var testSet = (set, version, options) => {
      for (let i = 0; i < set.length; i++) {
        if (!set[i].test(version)) {
          return false;
        }
      }
      if (version.prerelease.length && !options.includePrerelease) {
        for (let i = 0; i < set.length; i++) {
          debug(set[i].semver);
          if (set[i].semver === Comparator.ANY) {
            continue;
          }
          if (set[i].semver.prerelease.length > 0) {
            const allowed = set[i].semver;
            if (allowed.major === version.major && allowed.minor === version.minor && allowed.patch === version.patch) {
              return true;
            }
          }
        }
        return false;
      }
      return true;
    };
  }
});

// ../../node_modules/semver/classes/comparator.js
var require_comparator = __commonJS({
  "../../node_modules/semver/classes/comparator.js"(exports, module) {
    var ANY = Symbol("SemVer ANY");
    var Comparator = class _Comparator {
      static get ANY() {
        return ANY;
      }
      constructor(comp, options) {
        options = parseOptions(options);
        if (comp instanceof _Comparator) {
          if (comp.loose === !!options.loose) {
            return comp;
          } else {
            comp = comp.value;
          }
        }
        comp = comp.trim().split(/\s+/).join(" ");
        debug("comparator", comp, options);
        this.options = options;
        this.loose = !!options.loose;
        this.parse(comp);
        if (this.semver === ANY) {
          this.value = "";
        } else {
          this.value = this.operator + this.semver.version;
        }
        debug("comp", this);
      }
      parse(comp) {
        const r = this.options.loose ? re[t.COMPARATORLOOSE] : re[t.COMPARATOR];
        const m = comp.match(r);
        if (!m) {
          throw new TypeError(`Invalid comparator: ${comp}`);
        }
        this.operator = m[1] !== void 0 ? m[1] : "";
        if (this.operator === "=") {
          this.operator = "";
        }
        if (!m[2]) {
          this.semver = ANY;
        } else {
          this.semver = new SemVer(m[2], this.options.loose);
        }
      }
      toString() {
        return this.value;
      }
      test(version) {
        debug("Comparator.test", version, this.options.loose);
        if (this.semver === ANY || version === ANY) {
          return true;
        }
        if (typeof version === "string") {
          try {
            version = new SemVer(version, this.options);
          } catch (er) {
            return false;
          }
        }
        return cmp(version, this.operator, this.semver, this.options);
      }
      intersects(comp, options) {
        if (!(comp instanceof _Comparator)) {
          throw new TypeError("a Comparator is required");
        }
        if (this.operator === "") {
          if (this.value === "") {
            return true;
          }
          return new Range(comp.value, options).test(this.value);
        } else if (comp.operator === "") {
          if (comp.value === "") {
            return true;
          }
          return new Range(this.value, options).test(comp.semver);
        }
        options = parseOptions(options);
        if (options.includePrerelease && (this.value === "<0.0.0-0" || comp.value === "<0.0.0-0")) {
          return false;
        }
        if (!options.includePrerelease && (this.value.startsWith("<0.0.0") || comp.value.startsWith("<0.0.0"))) {
          return false;
        }
        if (this.operator.startsWith(">") && comp.operator.startsWith(">")) {
          return true;
        }
        if (this.operator.startsWith("<") && comp.operator.startsWith("<")) {
          return true;
        }
        if (this.semver.version === comp.semver.version && this.operator.includes("=") && comp.operator.includes("=")) {
          return true;
        }
        if (cmp(this.semver, "<", comp.semver, options) && this.operator.startsWith(">") && comp.operator.startsWith("<")) {
          return true;
        }
        if (cmp(this.semver, ">", comp.semver, options) && this.operator.startsWith("<") && comp.operator.startsWith(">")) {
          return true;
        }
        return false;
      }
    };
    module.exports = Comparator;
    var parseOptions = require_parse_options();
    var { safeRe: re, t } = require_re();
    var cmp = require_cmp();
    var debug = require_debug();
    var SemVer = require_semver();
    var Range = require_range();
  }
});

// ../../node_modules/semver/functions/satisfies.js
var require_satisfies = __commonJS({
  "../../node_modules/semver/functions/satisfies.js"(exports, module) {
    var Range = require_range();
    var satisfies = (version, range, options) => {
      try {
        range = new Range(range, options);
      } catch (er) {
        return false;
      }
      return range.test(version);
    };
    module.exports = satisfies;
  }
});

// ../../node_modules/semver/ranges/to-comparators.js
var require_to_comparators = __commonJS({
  "../../node_modules/semver/ranges/to-comparators.js"(exports, module) {
    var Range = require_range();
    var toComparators = (range, options) => new Range(range, options).set.map((comp) => comp.map((c) => c.value).join(" ").trim().split(" "));
    module.exports = toComparators;
  }
});

// ../../node_modules/semver/ranges/max-satisfying.js
var require_max_satisfying = __commonJS({
  "../../node_modules/semver/ranges/max-satisfying.js"(exports, module) {
    var SemVer = require_semver();
    var Range = require_range();
    var maxSatisfying = (versions, range, options) => {
      let max = null;
      let maxSV = null;
      let rangeObj = null;
      try {
        rangeObj = new Range(range, options);
      } catch (er) {
        return null;
      }
      versions.forEach((v) => {
        if (rangeObj.test(v)) {
          if (!max || maxSV.compare(v) === -1) {
            max = v;
            maxSV = new SemVer(max, options);
          }
        }
      });
      return max;
    };
    module.exports = maxSatisfying;
  }
});

// ../../node_modules/semver/ranges/min-satisfying.js
var require_min_satisfying = __commonJS({
  "../../node_modules/semver/ranges/min-satisfying.js"(exports, module) {
    var SemVer = require_semver();
    var Range = require_range();
    var minSatisfying = (versions, range, options) => {
      let min = null;
      let minSV = null;
      let rangeObj = null;
      try {
        rangeObj = new Range(range, options);
      } catch (er) {
        return null;
      }
      versions.forEach((v) => {
        if (rangeObj.test(v)) {
          if (!min || minSV.compare(v) === 1) {
            min = v;
            minSV = new SemVer(min, options);
          }
        }
      });
      return min;
    };
    module.exports = minSatisfying;
  }
});

// ../../node_modules/semver/ranges/min-version.js
var require_min_version = __commonJS({
  "../../node_modules/semver/ranges/min-version.js"(exports, module) {
    var SemVer = require_semver();
    var Range = require_range();
    var gt = require_gt();
    var minVersion = (range, loose) => {
      range = new Range(range, loose);
      let minver = new SemVer("0.0.0");
      if (range.test(minver)) {
        return minver;
      }
      minver = new SemVer("0.0.0-0");
      if (range.test(minver)) {
        return minver;
      }
      minver = null;
      for (let i = 0; i < range.set.length; ++i) {
        const comparators = range.set[i];
        let setMin = null;
        comparators.forEach((comparator) => {
          const compver = new SemVer(comparator.semver.version);
          switch (comparator.operator) {
            case ">":
              if (compver.prerelease.length === 0) {
                compver.patch++;
              } else {
                compver.prerelease.push(0);
              }
              compver.raw = compver.format();
            /* fallthrough */
            case "":
            case ">=":
              if (!setMin || gt(compver, setMin)) {
                setMin = compver;
              }
              break;
            case "<":
            case "<=":
              break;
            /* istanbul ignore next */
            default:
              throw new Error(`Unexpected operation: ${comparator.operator}`);
          }
        });
        if (setMin && (!minver || gt(minver, setMin))) {
          minver = setMin;
        }
      }
      if (minver && range.test(minver)) {
        return minver;
      }
      return null;
    };
    module.exports = minVersion;
  }
});

// ../../node_modules/semver/ranges/valid.js
var require_valid2 = __commonJS({
  "../../node_modules/semver/ranges/valid.js"(exports, module) {
    var Range = require_range();
    var validRange = (range, options) => {
      try {
        return new Range(range, options).range || "*";
      } catch (er) {
        return null;
      }
    };
    module.exports = validRange;
  }
});

// ../../node_modules/semver/ranges/outside.js
var require_outside = __commonJS({
  "../../node_modules/semver/ranges/outside.js"(exports, module) {
    var SemVer = require_semver();
    var Comparator = require_comparator();
    var { ANY } = Comparator;
    var Range = require_range();
    var satisfies = require_satisfies();
    var gt = require_gt();
    var lt = require_lt();
    var lte = require_lte();
    var gte = require_gte();
    var outside = (version, range, hilo, options) => {
      version = new SemVer(version, options);
      range = new Range(range, options);
      let gtfn, ltefn, ltfn, comp, ecomp;
      switch (hilo) {
        case ">":
          gtfn = gt;
          ltefn = lte;
          ltfn = lt;
          comp = ">";
          ecomp = ">=";
          break;
        case "<":
          gtfn = lt;
          ltefn = gte;
          ltfn = gt;
          comp = "<";
          ecomp = "<=";
          break;
        default:
          throw new TypeError('Must provide a hilo val of "<" or ">"');
      }
      if (satisfies(version, range, options)) {
        return false;
      }
      for (let i = 0; i < range.set.length; ++i) {
        const comparators = range.set[i];
        let high = null;
        let low = null;
        comparators.forEach((comparator) => {
          if (comparator.semver === ANY) {
            comparator = new Comparator(">=0.0.0");
          }
          high = high || comparator;
          low = low || comparator;
          if (gtfn(comparator.semver, high.semver, options)) {
            high = comparator;
          } else if (ltfn(comparator.semver, low.semver, options)) {
            low = comparator;
          }
        });
        if (high.operator === comp || high.operator === ecomp) {
          return false;
        }
        if ((!low.operator || low.operator === comp) && ltefn(version, low.semver)) {
          return false;
        } else if (low.operator === ecomp && ltfn(version, low.semver)) {
          return false;
        }
      }
      return true;
    };
    module.exports = outside;
  }
});

// ../../node_modules/semver/ranges/gtr.js
var require_gtr = __commonJS({
  "../../node_modules/semver/ranges/gtr.js"(exports, module) {
    var outside = require_outside();
    var gtr = (version, range, options) => outside(version, range, ">", options);
    module.exports = gtr;
  }
});

// ../../node_modules/semver/ranges/ltr.js
var require_ltr = __commonJS({
  "../../node_modules/semver/ranges/ltr.js"(exports, module) {
    var outside = require_outside();
    var ltr = (version, range, options) => outside(version, range, "<", options);
    module.exports = ltr;
  }
});

// ../../node_modules/semver/ranges/intersects.js
var require_intersects = __commonJS({
  "../../node_modules/semver/ranges/intersects.js"(exports, module) {
    var Range = require_range();
    var intersects = (r1, r2, options) => {
      r1 = new Range(r1, options);
      r2 = new Range(r2, options);
      return r1.intersects(r2, options);
    };
    module.exports = intersects;
  }
});

// ../../node_modules/semver/ranges/simplify.js
var require_simplify = __commonJS({
  "../../node_modules/semver/ranges/simplify.js"(exports, module) {
    var satisfies = require_satisfies();
    var compare = require_compare();
    module.exports = (versions, range, options) => {
      const set = [];
      let first = null;
      let prev = null;
      const v = versions.sort((a, b) => compare(a, b, options));
      for (const version of v) {
        const included = satisfies(version, range, options);
        if (included) {
          prev = version;
          if (!first) {
            first = version;
          }
        } else {
          if (prev) {
            set.push([first, prev]);
          }
          prev = null;
          first = null;
        }
      }
      if (first) {
        set.push([first, null]);
      }
      const ranges = [];
      for (const [min, max] of set) {
        if (min === max) {
          ranges.push(min);
        } else if (!max && min === v[0]) {
          ranges.push("*");
        } else if (!max) {
          ranges.push(`>=${min}`);
        } else if (min === v[0]) {
          ranges.push(`<=${max}`);
        } else {
          ranges.push(`${min} - ${max}`);
        }
      }
      const simplified = ranges.join(" || ");
      const original = typeof range.raw === "string" ? range.raw : String(range);
      return simplified.length < original.length ? simplified : range;
    };
  }
});

// ../../node_modules/semver/ranges/subset.js
var require_subset = __commonJS({
  "../../node_modules/semver/ranges/subset.js"(exports, module) {
    var Range = require_range();
    var Comparator = require_comparator();
    var { ANY } = Comparator;
    var satisfies = require_satisfies();
    var compare = require_compare();
    var subset = (sub, dom, options = {}) => {
      if (sub === dom) {
        return true;
      }
      sub = new Range(sub, options);
      dom = new Range(dom, options);
      let sawNonNull = false;
      OUTER: for (const simpleSub of sub.set) {
        for (const simpleDom of dom.set) {
          const isSub = simpleSubset(simpleSub, simpleDom, options);
          sawNonNull = sawNonNull || isSub !== null;
          if (isSub) {
            continue OUTER;
          }
        }
        if (sawNonNull) {
          return false;
        }
      }
      return true;
    };
    var minimumVersionWithPreRelease = [new Comparator(">=0.0.0-0")];
    var minimumVersion = [new Comparator(">=0.0.0")];
    var simpleSubset = (sub, dom, options) => {
      if (sub === dom) {
        return true;
      }
      if (sub.length === 1 && sub[0].semver === ANY) {
        if (dom.length === 1 && dom[0].semver === ANY) {
          return true;
        } else if (options.includePrerelease) {
          sub = minimumVersionWithPreRelease;
        } else {
          sub = minimumVersion;
        }
      }
      if (dom.length === 1 && dom[0].semver === ANY) {
        if (options.includePrerelease) {
          return true;
        } else {
          dom = minimumVersion;
        }
      }
      const eqSet = /* @__PURE__ */ new Set();
      let gt, lt;
      for (const c of sub) {
        if (c.operator === ">" || c.operator === ">=") {
          gt = higherGT(gt, c, options);
        } else if (c.operator === "<" || c.operator === "<=") {
          lt = lowerLT(lt, c, options);
        } else {
          eqSet.add(c.semver);
        }
      }
      if (eqSet.size > 1) {
        return null;
      }
      let gtltComp;
      if (gt && lt) {
        gtltComp = compare(gt.semver, lt.semver, options);
        if (gtltComp > 0) {
          return null;
        } else if (gtltComp === 0 && (gt.operator !== ">=" || lt.operator !== "<=")) {
          return null;
        }
      }
      for (const eq of eqSet) {
        if (gt && !satisfies(eq, String(gt), options)) {
          return null;
        }
        if (lt && !satisfies(eq, String(lt), options)) {
          return null;
        }
        for (const c of dom) {
          if (!satisfies(eq, String(c), options)) {
            return false;
          }
        }
        return true;
      }
      let higher, lower;
      let hasDomLT, hasDomGT;
      let needDomLTPre = lt && !options.includePrerelease && lt.semver.prerelease.length ? lt.semver : false;
      let needDomGTPre = gt && !options.includePrerelease && gt.semver.prerelease.length ? gt.semver : false;
      if (needDomLTPre && needDomLTPre.prerelease.length === 1 && lt.operator === "<" && needDomLTPre.prerelease[0] === 0) {
        needDomLTPre = false;
      }
      for (const c of dom) {
        hasDomGT = hasDomGT || c.operator === ">" || c.operator === ">=";
        hasDomLT = hasDomLT || c.operator === "<" || c.operator === "<=";
        if (gt) {
          if (needDomGTPre) {
            if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomGTPre.major && c.semver.minor === needDomGTPre.minor && c.semver.patch === needDomGTPre.patch) {
              needDomGTPre = false;
            }
          }
          if (c.operator === ">" || c.operator === ">=") {
            higher = higherGT(gt, c, options);
            if (higher === c && higher !== gt) {
              return false;
            }
          } else if (gt.operator === ">=" && !satisfies(gt.semver, String(c), options)) {
            return false;
          }
        }
        if (lt) {
          if (needDomLTPre) {
            if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomLTPre.major && c.semver.minor === needDomLTPre.minor && c.semver.patch === needDomLTPre.patch) {
              needDomLTPre = false;
            }
          }
          if (c.operator === "<" || c.operator === "<=") {
            lower = lowerLT(lt, c, options);
            if (lower === c && lower !== lt) {
              return false;
            }
          } else if (lt.operator === "<=" && !satisfies(lt.semver, String(c), options)) {
            return false;
          }
        }
        if (!c.operator && (lt || gt) && gtltComp !== 0) {
          return false;
        }
      }
      if (gt && hasDomLT && !lt && gtltComp !== 0) {
        return false;
      }
      if (lt && hasDomGT && !gt && gtltComp !== 0) {
        return false;
      }
      if (needDomGTPre || needDomLTPre) {
        return false;
      }
      return true;
    };
    var higherGT = (a, b, options) => {
      if (!a) {
        return b;
      }
      const comp = compare(a.semver, b.semver, options);
      return comp > 0 ? a : comp < 0 ? b : b.operator === ">" && a.operator === ">=" ? b : a;
    };
    var lowerLT = (a, b, options) => {
      if (!a) {
        return b;
      }
      const comp = compare(a.semver, b.semver, options);
      return comp < 0 ? a : comp > 0 ? b : b.operator === "<" && a.operator === "<=" ? b : a;
    };
    module.exports = subset;
  }
});

// ../../node_modules/semver/index.js
var require_semver2 = __commonJS({
  "../../node_modules/semver/index.js"(exports, module) {
    var internalRe = require_re();
    var constants = require_constants();
    var SemVer = require_semver();
    var identifiers = require_identifiers();
    var parse = require_parse();
    var valid = require_valid();
    var clean = require_clean();
    var inc = require_inc();
    var diff = require_diff();
    var major = require_major();
    var minor = require_minor();
    var patch = require_patch();
    var prerelease = require_prerelease();
    var compare = require_compare();
    var rcompare = require_rcompare();
    var compareLoose = require_compare_loose();
    var compareBuild = require_compare_build();
    var sort = require_sort();
    var rsort = require_rsort();
    var gt = require_gt();
    var lt = require_lt();
    var eq = require_eq();
    var neq = require_neq();
    var gte = require_gte();
    var lte = require_lte();
    var cmp = require_cmp();
    var coerce = require_coerce();
    var Comparator = require_comparator();
    var Range = require_range();
    var satisfies = require_satisfies();
    var toComparators = require_to_comparators();
    var maxSatisfying = require_max_satisfying();
    var minSatisfying = require_min_satisfying();
    var minVersion = require_min_version();
    var validRange = require_valid2();
    var outside = require_outside();
    var gtr = require_gtr();
    var ltr = require_ltr();
    var intersects = require_intersects();
    var simplifyRange = require_simplify();
    var subset = require_subset();
    module.exports = {
      parse,
      valid,
      clean,
      inc,
      diff,
      major,
      minor,
      patch,
      prerelease,
      compare,
      rcompare,
      compareLoose,
      compareBuild,
      sort,
      rsort,
      gt,
      lt,
      eq,
      neq,
      gte,
      lte,
      cmp,
      coerce,
      Comparator,
      Range,
      satisfies,
      toComparators,
      maxSatisfying,
      minSatisfying,
      minVersion,
      validRange,
      outside,
      gtr,
      ltr,
      intersects,
      simplifyRange,
      subset,
      SemVer,
      re: internalRe.re,
      src: internalRe.src,
      tokens: internalRe.t,
      SEMVER_SPEC_VERSION: constants.SEMVER_SPEC_VERSION,
      RELEASE_TYPES: constants.RELEASE_TYPES,
      compareIdentifiers: identifiers.compareIdentifiers,
      rcompareIdentifiers: identifiers.rcompareIdentifiers
    };
  }
});

// src/plugins/hook-system.ts
var HookSystemImpl = class {
  hooks = /* @__PURE__ */ new Map();
  executing = /* @__PURE__ */ new Set();
  /**
   * Register a hook handler
   */
  register(hookName, handler, priority = 10) {
    if (!this.hooks.has(hookName)) {
      this.hooks.set(hookName, []);
    }
    const hooks = this.hooks.get(hookName);
    const hook = {
      name: hookName,
      handler,
      priority
    };
    const insertIndex = hooks.findIndex((h) => h.priority > priority);
    if (insertIndex === -1) {
      hooks.push(hook);
    } else {
      hooks.splice(insertIndex, 0, hook);
    }
    console.debug(`Hook registered: ${hookName} (priority: ${priority})`);
  }
  /**
   * Execute all handlers for a hook
   */
  async execute(hookName, data, context) {
    const hooks = this.hooks.get(hookName);
    if (!hooks || hooks.length === 0) {
      return data;
    }
    if (this.executing.has(hookName)) {
      console.warn(`Hook recursion detected for: ${hookName}`);
      return data;
    }
    this.executing.add(hookName);
    try {
      let result = data;
      let cancelled = false;
      const hookContext = {
        plugin: "",
        // Will be set by the plugin manager
        context: context || {},
        cancel: () => {
          cancelled = true;
        }
      };
      for (const hook of hooks) {
        if (cancelled) {
          console.debug(`Hook execution cancelled: ${hookName}`);
          break;
        }
        try {
          console.debug(`Executing hook: ${hookName} (priority: ${hook.priority})`);
          result = await hook.handler(result, hookContext);
        } catch (error) {
          console.error(`Hook execution failed: ${hookName}`, error);
          if (error instanceof Error && error.message.includes("CRITICAL")) {
            throw error;
          }
        }
      }
      return result;
    } finally {
      this.executing.delete(hookName);
    }
  }
  /**
   * Remove a hook handler
   */
  unregister(hookName, handler) {
    const hooks = this.hooks.get(hookName);
    if (!hooks) return;
    const index = hooks.findIndex((h) => h.handler === handler);
    if (index !== -1) {
      hooks.splice(index, 1);
      console.debug(`Hook unregistered: ${hookName}`);
    }
    if (hooks.length === 0) {
      this.hooks.delete(hookName);
    }
  }
  /**
   * Get all registered hooks for a name
   */
  getHooks(hookName) {
    return this.hooks.get(hookName) || [];
  }
  /**
   * Get all registered hook names
   */
  getHookNames() {
    return Array.from(this.hooks.keys());
  }
  /**
   * Get hook statistics
   */
  getStats() {
    return Array.from(this.hooks.entries()).map(([hookName, handlers]) => ({
      hookName,
      handlerCount: handlers.length
    }));
  }
  /**
   * Clear all hooks (useful for testing)
   */
  clear() {
    this.hooks.clear();
    this.executing.clear();
  }
  /**
   * Create a scoped hook system for a plugin
   */
  createScope(_pluginName) {
    return new ScopedHookSystem(this);
  }
};
var ScopedHookSystem = class {
  constructor(parent) {
    this.parent = parent;
  }
  registeredHooks = [];
  /**
   * Register a hook (scoped to this plugin)
   */
  register(hookName, handler, priority) {
    this.parent.register(hookName, handler, priority);
    this.registeredHooks.push({ hookName, handler });
  }
  /**
   * Execute a hook
   */
  async execute(hookName, data, context) {
    return this.parent.execute(hookName, data, context);
  }
  /**
   * Unregister a specific hook
   */
  unregister(hookName, handler) {
    this.parent.unregister(hookName, handler);
    const index = this.registeredHooks.findIndex(
      (h) => h.hookName === hookName && h.handler === handler
    );
    if (index !== -1) {
      this.registeredHooks.splice(index, 1);
    }
  }
  /**
   * Unregister all hooks for this plugin
   */
  unregisterAll() {
    for (const { hookName, handler } of this.registeredHooks) {
      this.parent.unregister(hookName, handler);
    }
    this.registeredHooks.length = 0;
  }
  /**
   * Get hooks registered by this plugin
   */
  getRegisteredHooks() {
    return [...this.registeredHooks];
  }
};
var HookUtils = class {
  /**
   * Create a hook name with namespace
   */
  static createHookName(namespace, event) {
    return `${namespace}:${event}`;
  }
  /**
   * Parse a hook name to extract namespace and event
   */
  static parseHookName(hookName) {
    const parts = hookName.split(":");
    return {
      namespace: parts[0] || "",
      event: parts.slice(1).join(":") || ""
    };
  }
  /**
   * Create a middleware that executes hooks
   */
  static createHookMiddleware(hookSystem, beforeHook, afterHook) {
    return async (c, next) => {
      if (beforeHook) {
        const beforeData = { request: c.req, context: c };
        await hookSystem.execute(beforeHook, beforeData);
      }
      await next();
      if (afterHook) {
        const afterData = { request: c.req, response: c.res, context: c };
        await hookSystem.execute(afterHook, afterData);
      }
    };
  }
  /**
   * Create a debounced hook handler
   */
  static debounce(handler, delay) {
    let timeoutId;
    return async (data, context) => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      return new Promise((resolve, reject) => {
        timeoutId = setTimeout(async () => {
          try {
            const result = await handler(data, context);
            resolve(result);
          } catch (error) {
            reject(error);
          }
        }, delay);
      });
    };
  }
  /**
   * Create a throttled hook handler
   */
  static throttle(handler, limit) {
    let lastExecution = 0;
    return async (data, context) => {
      const now = Date.now();
      if (now - lastExecution >= limit) {
        lastExecution = now;
        return handler(data, context);
      }
      return data;
    };
  }
};

// src/plugins/plugin-validator.ts
var import_semver = __toESM(require_semver2(), 1);
var PluginAuthorSchema = z.object({
  name: z.string().min(1),
  email: z.string().email().optional(),
  url: z.string().url().optional()
});
var PluginRoutesSchema = z.object({
  path: z.string().min(1),
  handler: z.any(),
  // Hono instance
  description: z.string().optional(),
  requiresAuth: z.boolean().optional(),
  roles: z.array(z.string()).optional(),
  priority: z.number().optional()
});
var PluginMiddlewareSchema = z.object({
  name: z.string().min(1),
  handler: z.function(),
  description: z.string().optional(),
  priority: z.number().optional(),
  routes: z.array(z.string()).optional(),
  global: z.boolean().optional()
});
var PluginModelSchema = z.object({
  name: z.string().min(1),
  tableName: z.string().min(1),
  schema: z.any(),
  // Zod schema
  migrations: z.array(z.string()),
  relationships: z.array(z.object({
    type: z.enum(["oneToOne", "oneToMany", "manyToMany"]),
    target: z.string(),
    foreignKey: z.string().optional(),
    joinTable: z.string().optional()
  })).optional(),
  extendsContent: z.boolean().optional()
});
var PluginServiceSchema = z.object({
  name: z.string().min(1),
  implementation: z.any(),
  description: z.string().optional(),
  dependencies: z.array(z.string()).optional(),
  singleton: z.boolean().optional()
});
var PluginAdminPageSchema = z.object({
  path: z.string().min(1),
  title: z.string().min(1),
  component: z.string().min(1),
  description: z.string().optional(),
  permissions: z.array(z.string()).optional(),
  menuItem: z.object({
    label: z.string(),
    path: z.string(),
    icon: z.string().optional(),
    order: z.number().optional(),
    parent: z.string().optional(),
    permissions: z.array(z.string()).optional(),
    active: z.boolean().optional()
  }).optional(),
  icon: z.string().optional()
});
var PluginComponentSchema = z.object({
  name: z.string().min(1),
  template: z.function(),
  description: z.string().optional(),
  propsSchema: z.any().optional()
  // Zod schema
});
var PluginHookSchema = z.object({
  name: z.string().min(1),
  handler: z.function(),
  priority: z.number().optional(),
  description: z.string().optional()
});
var PluginSchema = z.object({
  name: z.string().min(1).regex(/^[a-z0-9-]+$/, "Plugin name must be lowercase with hyphens"),
  version: z.string().refine((v) => import_semver.default.valid(v), "Version must be valid semver"),
  description: z.string().optional(),
  author: PluginAuthorSchema.optional(),
  dependencies: z.array(z.string()).optional(),
  compatibility: z.string().optional(),
  license: z.string().optional(),
  // Extension points
  routes: z.array(PluginRoutesSchema).optional(),
  middleware: z.array(PluginMiddlewareSchema).optional(),
  models: z.array(PluginModelSchema).optional(),
  services: z.array(PluginServiceSchema).optional(),
  adminPages: z.array(PluginAdminPageSchema).optional(),
  adminComponents: z.array(PluginComponentSchema).optional(),
  menuItems: z.array(z.object({
    label: z.string(),
    path: z.string(),
    icon: z.string().optional(),
    order: z.number().optional(),
    parent: z.string().optional(),
    permissions: z.array(z.string()).optional(),
    active: z.boolean().optional()
  })).optional(),
  hooks: z.array(PluginHookSchema).optional(),
  // Lifecycle hooks
  install: z.function().optional(),
  uninstall: z.function().optional(),
  activate: z.function().optional(),
  deactivate: z.function().optional(),
  configure: z.function().optional()
});
var PluginValidator = class _PluginValidator {
  static RESERVED_NAMES = [
    "core",
    "system",
    "admin",
    "api",
    "auth",
    "content",
    "media",
    "users",
    "collections"
  ];
  static RESERVED_PATHS = [
    "/admin",
    "/api",
    "/auth",
    "/docs",
    "/media",
    "/_assets"
  ];
  /**
   * Validate plugin definition
   */
  validate(plugin) {
    const errors = [];
    const warnings = [];
    try {
      const result = PluginSchema.safeParse(plugin);
      if (!result.success) {
        result.error.issues.forEach((err) => {
          errors.push(`${err.path.join(".")}: ${err.message}`);
        });
      }
      if (_PluginValidator.RESERVED_NAMES.includes(plugin.name)) {
        errors.push(`Plugin name "${plugin.name}" is reserved`);
      }
      if (plugin.routes) {
        for (const route of plugin.routes) {
          if (_PluginValidator.RESERVED_PATHS.some((path) => route.path.startsWith(path))) {
            errors.push(`Route path "${route.path}" conflicts with reserved system path`);
          }
          if (!route.path.startsWith("/")) {
            errors.push(`Route path "${route.path}" must start with /`);
          }
        }
      }
      if (plugin.models) {
        const modelNames = /* @__PURE__ */ new Set();
        const tableNames = /* @__PURE__ */ new Set();
        for (const model of plugin.models) {
          if (modelNames.has(model.name)) {
            errors.push(`Duplicate model name: ${model.name}`);
          }
          modelNames.add(model.name);
          if (tableNames.has(model.tableName)) {
            errors.push(`Duplicate table name: ${model.tableName}`);
          }
          tableNames.add(model.tableName);
          if (!/^[a-z][a-z0-9_]*$/.test(model.tableName)) {
            errors.push(`Invalid table name format: ${model.tableName}`);
          }
          const systemTables = ["users", "collections", "content", "content_versions", "media", "api_tokens"];
          if (systemTables.includes(model.tableName)) {
            errors.push(`Table name "${model.tableName}" conflicts with system table`);
          }
        }
      }
      if (plugin.services) {
        const serviceNames = /* @__PURE__ */ new Set();
        for (const service of plugin.services) {
          if (serviceNames.has(service.name)) {
            errors.push(`Duplicate service name: ${service.name}`);
          }
          serviceNames.add(service.name);
          const systemServices = ["auth", "content", "media", "cdn"];
          if (systemServices.includes(service.name)) {
            warnings.push(`Service name "${service.name}" conflicts with system service`);
          }
        }
      }
      if (plugin.adminPages) {
        const pagePaths = /* @__PURE__ */ new Set();
        for (const page of plugin.adminPages) {
          if (pagePaths.has(page.path)) {
            errors.push(`Duplicate admin page path: ${page.path}`);
          }
          pagePaths.add(page.path);
          if (!page.path.startsWith("/")) {
            errors.push(`Admin page path "${page.path}" must start with /`);
          }
          const systemPaths = ["/", "/collections", "/content", "/media", "/users", "/settings"];
          if (systemPaths.includes(page.path)) {
            errors.push(`Admin page path "${page.path}" conflicts with system page`);
          }
        }
      }
      if (plugin.adminComponents) {
        const componentNames = /* @__PURE__ */ new Set();
        for (const component of plugin.adminComponents) {
          if (componentNames.has(component.name)) {
            errors.push(`Duplicate component name: ${component.name}`);
          }
          componentNames.add(component.name);
          const systemComponents = ["table", "form", "alert", "media-grid", "pagination"];
          if (systemComponents.includes(component.name)) {
            warnings.push(`Component name "${component.name}" conflicts with system component`);
          }
        }
      }
      if (plugin.hooks) {
        for (const hook of plugin.hooks) {
          if (!hook.name.includes(":")) {
            warnings.push(`Hook name "${hook.name}" should include namespace (e.g., "plugin:event")`);
          }
        }
      }
      if (plugin.dependencies?.includes(plugin.name)) {
        errors.push(`Plugin cannot depend on itself`);
      }
      if (plugin.license) {
        const validLicenses = ["MIT", "Apache-2.0", "GPL-3.0", "BSD-3-Clause", "ISC"];
        if (!validLicenses.includes(plugin.license)) {
          warnings.push(`License "${plugin.license}" is not a common SPDX identifier`);
        }
      }
      if (plugin.middleware && plugin.middleware.length > 5) {
        warnings.push(`Plugin defines ${plugin.middleware.length} middleware functions, consider consolidating`);
      }
      if (plugin.hooks && plugin.hooks.length > 10) {
        warnings.push(`Plugin defines ${plugin.hooks.length} hooks, ensure they are necessary`);
      }
    } catch (error) {
      errors.push(`Validation error: ${error instanceof Error ? error.message : String(error)}`);
    }
    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }
  /**
   * Validate plugin dependencies
   */
  validateDependencies(plugin, registry) {
    const errors = [];
    const warnings = [];
    if (!plugin.dependencies || plugin.dependencies.length === 0) {
      return { valid: true, errors, warnings };
    }
    for (const depName of plugin.dependencies) {
      if (!registry.has(depName)) {
        errors.push(`Dependency "${depName}" is not registered`);
        continue;
      }
      const dependency = registry.get(depName);
      if (dependency.compatibility && plugin.compatibility) {
        if (!this.isCompatible(dependency.compatibility, plugin.compatibility)) {
          warnings.push(`Potential compatibility issue with dependency "${depName}"`);
        }
      }
    }
    const visited = /* @__PURE__ */ new Set();
    const visiting = /* @__PURE__ */ new Set();
    const checkCircular = (name) => {
      if (visiting.has(name)) return true;
      if (visited.has(name)) return false;
      visiting.add(name);
      const current = registry.get(name);
      if (current?.dependencies) {
        for (const depName of current.dependencies) {
          if (checkCircular(depName)) {
            errors.push(`Circular dependency detected: ${name} -> ${depName}`);
            return true;
          }
        }
      }
      visiting.delete(name);
      visited.add(name);
      return false;
    };
    checkCircular(plugin.name);
    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }
  /**
   * Validate plugin compatibility with SonicJS version
   */
  validateCompatibility(plugin, sonicVersion) {
    const errors = [];
    const warnings = [];
    if (!plugin.compatibility) {
      warnings.push("Plugin does not specify compatibility version");
      return { valid: true, errors, warnings };
    }
    try {
      if (!import_semver.default.satisfies(sonicVersion, plugin.compatibility)) {
        errors.push(`Plugin requires SonicJS ${plugin.compatibility}, but current version is ${sonicVersion}`);
      }
    } catch (error) {
      errors.push(`Invalid compatibility version format: ${plugin.compatibility}`);
    }
    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }
  /**
   * Check if two version ranges are compatible
   */
  isCompatible(version1, version2) {
    try {
      return import_semver.default.intersects(version1, version2);
    } catch {
      return false;
    }
  }
  /**
   * Validate plugin security constraints
   */
  validateSecurity(plugin) {
    const errors = [];
    const warnings = [];
    const pluginCode = JSON.stringify(plugin);
    if (pluginCode.includes("eval(") || pluginCode.includes("Function(")) {
      errors.push("Plugin contains potentially dangerous code execution patterns");
    }
    if (pluginCode.includes("fs.") || pluginCode.includes("require(")) {
      warnings.push("Plugin may attempt file system access (not available in Cloudflare Workers)");
    }
    if (pluginCode.includes("fetch(") || pluginCode.includes("XMLHttpRequest")) {
      warnings.push("Plugin contains network access code - ensure it follows security guidelines");
    }
    const sensitivePatterns = ["password", "secret", "key", "token", "credential"];
    for (const pattern of sensitivePatterns) {
      if (pluginCode.toLowerCase().includes(pattern)) {
        warnings.push(`Plugin code contains "${pattern}" - ensure sensitive data is properly handled`);
      }
    }
    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }
};

// src/plugins/plugin-registry.ts
var PluginRegistryImpl = class {
  plugins = /* @__PURE__ */ new Map();
  configs = /* @__PURE__ */ new Map();
  statuses = /* @__PURE__ */ new Map();
  validator;
  constructor(validator) {
    this.validator = validator || new PluginValidator();
  }
  /**
   * Get plugin by name
   */
  get(name) {
    return this.plugins.get(name);
  }
  /**
   * Get all registered plugins
   */
  getAll() {
    return Array.from(this.plugins.values());
  }
  /**
   * Get active plugins
   */
  getActive() {
    return this.getAll().filter((plugin) => {
      const status = this.statuses.get(plugin.name);
      return status?.active === true;
    });
  }
  /**
   * Register a plugin
   */
  async register(plugin) {
    console.info(`Registering plugin: ${plugin.name} v${plugin.version}`);
    const validation = this.validator.validate(plugin);
    if (!validation.valid) {
      throw new Error(`Plugin validation failed for ${plugin.name}: ${validation.errors.join(", ")}`);
    }
    if (this.plugins.has(plugin.name)) {
      const existingPlugin = this.plugins.get(plugin.name);
      if (existingPlugin.version !== plugin.version) {
        console.warn(`Plugin ${plugin.name} is already registered with version ${existingPlugin.version}, replacing with ${plugin.version}`);
      }
    }
    const depValidation = this.validator.validateDependencies(plugin, this);
    if (!depValidation.valid) {
      throw new Error(`Plugin dependency validation failed for ${plugin.name}: ${depValidation.errors.join(", ")}`);
    }
    this.plugins.set(plugin.name, plugin);
    this.statuses.set(plugin.name, {
      name: plugin.name,
      version: plugin.version,
      active: false,
      installed: true,
      hasErrors: false,
      errors: []
    });
    console.info(`Plugin registered successfully: ${plugin.name}`);
  }
  /**
   * Unregister a plugin
   */
  async unregister(name) {
    console.info(`Unregistering plugin: ${name}`);
    if (!this.plugins.has(name)) {
      throw new Error(`Plugin not found: ${name}`);
    }
    const dependents = this.getDependents(name);
    if (dependents.length > 0) {
      throw new Error(`Cannot unregister ${name}: plugins ${dependents.join(", ")} depend on it`);
    }
    this.plugins.delete(name);
    this.configs.delete(name);
    this.statuses.delete(name);
    console.info(`Plugin unregistered: ${name}`);
  }
  /**
   * Check if plugin is registered
   */
  has(name) {
    return this.plugins.has(name);
  }
  /**
   * Activate a plugin
   */
  async activate(name) {
    console.info(`Activating plugin: ${name}`);
    const plugin = this.plugins.get(name);
    if (!plugin) {
      throw new Error(`Plugin not found: ${name}`);
    }
    const status = this.statuses.get(name);
    if (status?.active) {
      console.warn(`Plugin ${name} is already active`);
      return;
    }
    try {
      if (plugin.dependencies) {
        for (const depName of plugin.dependencies) {
          const depStatus = this.statuses.get(depName);
          if (!depStatus?.active) {
            await this.activate(depName);
          }
        }
      }
      this.updateStatus(name, {
        active: true,
        hasErrors: false,
        errors: []
      });
      console.info(`Plugin activated: ${name}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.updateStatus(name, {
        active: false,
        hasErrors: true,
        errors: [errorMessage],
        lastError: errorMessage
      });
      throw new Error(`Failed to activate plugin ${name}: ${errorMessage}`);
    }
  }
  /**
   * Deactivate a plugin
   */
  async deactivate(name) {
    console.info(`Deactivating plugin: ${name}`);
    const plugin = this.plugins.get(name);
    if (!plugin) {
      throw new Error(`Plugin not found: ${name}`);
    }
    const status = this.statuses.get(name);
    if (!status?.active) {
      console.warn(`Plugin ${name} is not active`);
      return;
    }
    try {
      const dependents = this.getDependents(name);
      for (const depName of dependents) {
        const depStatus = this.statuses.get(depName);
        if (depStatus?.active) {
          await this.deactivate(depName);
        }
      }
      this.updateStatus(name, {
        active: false,
        hasErrors: false,
        errors: []
      });
      console.info(`Plugin deactivated: ${name}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.updateStatus(name, {
        hasErrors: true,
        errors: [errorMessage],
        lastError: errorMessage
      });
      throw new Error(`Failed to deactivate plugin ${name}: ${errorMessage}`);
    }
  }
  /**
   * Get plugin configuration
   */
  getConfig(name) {
    return this.configs.get(name);
  }
  /**
   * Set plugin configuration
   */
  setConfig(name, config) {
    this.configs.set(name, {
      ...config,
      updatedAt: Date.now()
    });
  }
  /**
   * Get plugin status
   */
  getStatus(name) {
    return this.statuses.get(name);
  }
  /**
   * Get all plugin statuses
   */
  getAllStatuses() {
    return new Map(this.statuses);
  }
  /**
   * Update plugin status
   */
  updateStatus(name, updates) {
    const current = this.statuses.get(name);
    if (current) {
      this.statuses.set(name, { ...current, ...updates });
    }
  }
  /**
   * Get plugins that depend on the specified plugin
   */
  getDependents(name) {
    const dependents = [];
    for (const [pluginName, plugin] of this.plugins) {
      if (plugin.dependencies?.includes(name)) {
        dependents.push(pluginName);
      }
    }
    return dependents;
  }
  /**
   * Get dependency graph
   */
  getDependencyGraph() {
    const graph = /* @__PURE__ */ new Map();
    for (const [name, plugin] of this.plugins) {
      graph.set(name, plugin.dependencies || []);
    }
    return graph;
  }
  /**
   * Resolve plugin load order based on dependencies
   */
  resolveLoadOrder() {
    const graph = this.getDependencyGraph();
    const visited = /* @__PURE__ */ new Set();
    const visiting = /* @__PURE__ */ new Set();
    const result = [];
    const visit = (name) => {
      if (visited.has(name)) return;
      if (visiting.has(name)) {
        throw new Error(`Circular dependency detected involving plugin: ${name}`);
      }
      visiting.add(name);
      const dependencies = graph.get(name) || [];
      for (const dep of dependencies) {
        if (!graph.has(dep)) {
          throw new Error(`Plugin ${name} depends on ${dep}, but ${dep} is not registered`);
        }
        visit(dep);
      }
      visiting.delete(name);
      visited.add(name);
      result.push(name);
    };
    for (const name of graph.keys()) {
      visit(name);
    }
    return result;
  }
  /**
   * Export plugin configuration
   */
  exportConfig() {
    const plugins = [];
    for (const [name, config] of this.configs) {
      plugins.push({
        ...config,
        name
      });
    }
    return { plugins };
  }
  /**
   * Import plugin configuration
   */
  importConfig(config) {
    for (const pluginConfig of config.plugins) {
      if ("name" in pluginConfig) {
        const { name, ...rest } = pluginConfig;
        this.setConfig(name, rest);
      }
    }
  }
  /**
   * Clear all plugins (useful for testing)
   */
  clear() {
    this.plugins.clear();
    this.configs.clear();
    this.statuses.clear();
  }
  /**
   * Get registry statistics
   */
  getStats() {
    const statuses = Array.from(this.statuses.values());
    return {
      total: statuses.length,
      active: statuses.filter((s) => s.active).length,
      inactive: statuses.filter((s) => !s.active).length,
      withErrors: statuses.filter((s) => s.hasErrors).length
    };
  }
};
var PluginManager = class {
  registry;
  hooks;
  validator;
  context;
  scopedHooks = /* @__PURE__ */ new Map();
  pluginRoutes = /* @__PURE__ */ new Map();
  constructor() {
    this.validator = new PluginValidator();
    this.registry = new PluginRegistryImpl(this.validator);
    this.hooks = new HookSystemImpl();
  }
  /**
   * Initialize plugin system
   */
  async initialize(context) {
    console.info("Initializing plugin system...");
    this.context = context;
    await this.hooks.execute(HOOKS.APP_INIT, {
      pluginManager: this,
      context
    });
    console.info("Plugin system initialized");
  }
  /**
   * Load plugins from configuration
   */
  async loadPlugins(configs) {
    console.info(`Loading ${configs.length} plugins...`);
    const enabledConfigs = configs.filter((config) => config.enabled);
    if (enabledConfigs.length === 0) {
      console.info("No enabled plugins to load");
      return;
    }
    for (const config of enabledConfigs) {
      try {
        console.info(`Loading plugin configuration: ${JSON.stringify(config)}`);
        if ("name" in config) {
          this.registry.setConfig(config.name, config);
        }
      } catch (error) {
        console.error(`Failed to load plugin configuration:`, error);
      }
    }
    try {
      const loadOrder = this.registry.resolveLoadOrder();
      console.info(`Plugin load order: ${loadOrder.join(" -> ")}`);
      for (const pluginName of loadOrder) {
        const config = this.registry.getConfig(pluginName);
        if (config?.enabled) {
          await this.registry.activate(pluginName);
        }
      }
    } catch (error) {
      console.error("Failed to resolve plugin load order:", error);
    }
    console.info("Plugin loading completed");
  }
  /**
   * Install a plugin
   */
  async install(plugin, config) {
    console.info(`Installing plugin: ${plugin.name}`);
    if (!this.context) {
      throw new Error("Plugin manager not initialized");
    }
    try {
      const validation = this.validator.validate(plugin);
      if (!validation.valid) {
        throw new Error(`Plugin validation failed: ${validation.errors.join(", ")}`);
      }
      await this.registry.register(plugin);
      const pluginConfig = {
        enabled: true,
        installedAt: Date.now(),
        ...config
      };
      this.registry.setConfig(plugin.name, pluginConfig);
      const scopedHooks = this.hooks.createScope ? this.hooks.createScope(plugin.name) : this.hooks;
      this.scopedHooks.set(plugin.name, scopedHooks);
      const pluginContext = {
        ...this.context,
        config: pluginConfig,
        hooks: scopedHooks,
        logger: this.createLogger(plugin.name)
      };
      await this.registerPluginExtensions(plugin, pluginContext);
      if (plugin.install) {
        await plugin.install(pluginContext);
      }
      await this.hooks.execute(HOOKS.PLUGIN_INSTALL, {
        plugin: plugin.name,
        version: plugin.version,
        context: pluginContext
      });
      console.info(`Plugin installed successfully: ${plugin.name}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error(`Failed to install plugin ${plugin.name}:`, errorMessage);
      const status = this.registry.getStatus(plugin.name);
      if (status) {
        this.updatePluginStatus(plugin.name, {
          hasErrors: true,
          errors: [...status.errors || [], errorMessage],
          lastError: errorMessage
        });
      }
      throw error;
    }
  }
  /**
   * Uninstall a plugin
   */
  async uninstall(name) {
    console.info(`Uninstalling plugin: ${name}`);
    const plugin = this.registry.get(name);
    if (!plugin) {
      throw new Error(`Plugin not found: ${name}`);
    }
    if (!this.context) {
      throw new Error("Plugin manager not initialized");
    }
    try {
      const status = this.registry.getStatus(name);
      if (status?.active) {
        await this.registry.deactivate(name);
      }
      const config = this.registry.getConfig(name) || { enabled: false };
      const pluginContext = {
        ...this.context,
        config,
        hooks: this.scopedHooks.get(name) || this.hooks,
        logger: this.createLogger(name)
      };
      if (plugin.uninstall) {
        await plugin.uninstall(pluginContext);
      }
      await this.unregisterPluginExtensions(plugin);
      const scopedHooks = this.scopedHooks.get(name);
      if (scopedHooks && "unregisterAll" in scopedHooks) {
        scopedHooks.unregisterAll();
      }
      this.scopedHooks.delete(name);
      this.pluginRoutes.delete(name);
      await this.hooks.execute(HOOKS.PLUGIN_UNINSTALL, {
        plugin: name,
        context: pluginContext
      });
      await this.registry.unregister(name);
      console.info(`Plugin uninstalled successfully: ${name}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error(`Failed to uninstall plugin ${name}:`, errorMessage);
      throw error;
    }
  }
  /**
   * Get plugin status
   */
  getStatus(name) {
    const status = this.registry.getStatus(name);
    if (!status) {
      return {
        name,
        version: "unknown",
        active: false,
        installed: false,
        hasErrors: false
      };
    }
    return status;
  }
  /**
   * Get all plugin statuses
   */
  getAllStatuses() {
    return Array.from(this.registry.getAllStatuses().values());
  }
  /**
   * Register plugin extensions (routes, middleware, etc.)
   */
  async registerPluginExtensions(plugin, _context) {
    if (plugin.routes) {
      const pluginApp = new Hono();
      for (const route of plugin.routes) {
        console.debug(`Registering plugin route: ${route.path}`);
        pluginApp.route(route.path, route.handler);
      }
      this.pluginRoutes.set(plugin.name, pluginApp);
    }
    if (plugin.middleware) {
      for (const middleware of plugin.middleware) {
        console.debug(`Registering plugin middleware: ${middleware.name}`);
      }
    }
    if (plugin.hooks) {
      const scopedHooks = this.scopedHooks.get(plugin.name);
      for (const hook of plugin.hooks) {
        console.debug(`Registering plugin hook: ${hook.name}`);
        if (scopedHooks) {
          scopedHooks.register(hook.name, hook.handler, hook.priority);
        } else {
          this.hooks.register(hook.name, hook.handler, hook.priority);
        }
      }
    }
    if (plugin.services) {
      for (const service of plugin.services) {
        console.debug(`Registering plugin service: ${service.name}`);
      }
    }
    if (plugin.models) {
      for (const model of plugin.models) {
        console.debug(`Registering plugin model: ${model.name}`);
      }
    }
  }
  /**
   * Unregister plugin extensions
   */
  async unregisterPluginExtensions(plugin) {
    console.debug(`Unregistering extensions for plugin: ${plugin.name}`);
  }
  /**
   * Update plugin status
   */
  updatePluginStatus(name, updates) {
    const current = this.registry.getStatus(name);
    if (current && "updateStatus" in this.registry) {
      console.debug(`Updating status for plugin: ${name}`, updates);
    }
  }
  /**
   * Create a logger for a plugin
   */
  createLogger(pluginName) {
    return {
      debug: (message, data) => {
        console.debug(`[Plugin:${pluginName}] ${message}`, data || "");
      },
      info: (message, data) => {
        console.info(`[Plugin:${pluginName}] ${message}`, data || "");
      },
      warn: (message, data) => {
        console.warn(`[Plugin:${pluginName}] ${message}`, data || "");
      },
      error: (message, error, data) => {
        console.error(`[Plugin:${pluginName}] ${message}`, error || "", data || "");
      }
    };
  }
  /**
   * Get plugin routes for mounting in main app
   */
  getPluginRoutes() {
    return new Map(this.pluginRoutes);
  }
  /**
   * Get plugin middleware for main app
   */
  getPluginMiddleware() {
    const middleware = [];
    for (const plugin of this.registry.getActive()) {
      if (plugin.middleware) {
        for (const mw of plugin.middleware) {
          middleware.push({
            name: `${plugin.name}:${mw.name}`,
            handler: mw.handler,
            priority: mw.priority || 10,
            global: mw.global || false
          });
        }
      }
    }
    return middleware.sort((a, b) => a.priority - b.priority);
  }
  /**
   * Execute shutdown procedures
   */
  async shutdown() {
    console.info("Shutting down plugin system...");
    await this.hooks.execute(HOOKS.APP_SHUTDOWN, {
      pluginManager: this
    });
    const activePlugins = this.registry.getActive();
    for (const plugin of activePlugins.reverse()) {
      try {
        await this.registry.deactivate(plugin.name);
      } catch (error) {
        console.error(`Error deactivating plugin ${plugin.name}:`, error);
      }
    }
    console.info("Plugin system shutdown completed");
  }
  /**
   * Get plugin system statistics
   */
  getStats() {
    return {
      registry: this.registry.getStats(),
      hooks: this.hooks.getStats(),
      routes: this.pluginRoutes.size,
      middleware: this.getPluginMiddleware().length
    };
  }
};

// src/plugins/core-plugins/turnstile-plugin/middleware/verify.ts
async function verifyTurnstile(c, next) {
  const db = c.get("db") || c.env?.DB;
  if (!db) {
    console.error("Turnstile middleware: Database not available");
    return c.json({ error: "Database not available" }, 500);
  }
  const turnstileService = new TurnstileService(db);
  const isEnabled = await turnstileService.isEnabled();
  if (!isEnabled) {
    return next();
  }
  let token;
  let body;
  if (c.req.method === "POST") {
    const contentType = c.req.header("content-type") || "";
    if (contentType.includes("application/json")) {
      body = await c.req.json();
      token = body["cf-turnstile-response"] || body["turnstile-token"];
      c.set("requestBody", body);
    } else if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
      const formData = await c.req.formData();
      token = formData.get("cf-turnstile-response")?.toString() || formData.get("turnstile-token")?.toString();
    }
  }
  if (!token) {
    return c.json({
      error: "Turnstile token missing",
      message: "Please complete the verification challenge"
    }, 400);
  }
  const remoteIp = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for");
  const result = await turnstileService.verifyToken(token, remoteIp);
  if (!result.success) {
    return c.json({
      error: "Turnstile verification failed",
      message: result.error || "Verification failed. Please try again."
    }, 403);
  }
  return next();
}
function createTurnstileMiddleware(options) {
  return async (c, next) => {
    const db = c.get("db") || c.env?.DB;
    if (!db) {
      return options?.onError?.(c, "Database not available") || c.json({ error: "Database not available" }, 500);
    }
    const turnstileService = new TurnstileService(db);
    const isEnabled = await turnstileService.isEnabled();
    if (!isEnabled) {
      return next();
    }
    let token;
    const contentType = c.req.header("content-type") || "";
    if (contentType.includes("application/json")) {
      const body = await c.req.json();
      token = body["cf-turnstile-response"] || body["turnstile-token"];
      c.set("requestBody", body);
    } else if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
      const formData = await c.req.formData();
      token = formData.get("cf-turnstile-response")?.toString() || formData.get("turnstile-token")?.toString();
    }
    if (!token) {
      return options?.onMissing?.(c) || c.json({ error: "Turnstile token missing" }, 400);
    }
    const remoteIp = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for");
    const result = await turnstileService.verifyToken(token, remoteIp);
    if (!result.success) {
      return options?.onError?.(c, result.error || "Verification failed") || c.json({ error: "Turnstile verification failed", message: result.error }, 403);
    }
    return next();
  };
}

// src/plugins/core-plugins/turnstile-plugin/index.ts
new PluginBuilder({
  name: manifest_default.name,
  version: manifest_default.version,
  description: manifest_default.description,
  author: { name: manifest_default.author }
}).metadata({
  description: manifest_default.description,
  author: { name: manifest_default.author }
}).addService("turnstile", TurnstileService).addSingleMiddleware("verifyTurnstile", verifyTurnstile, {
  description: "Verify Cloudflare Turnstile token",
  global: false
}).build();

export { HookSystemImpl, HookUtils, PluginManager, PluginRegistryImpl, PluginValidator, ScopedHookSystem, createTurnstileMiddleware, verifyTurnstile };
//# sourceMappingURL=chunk-CJYFSKH7.js.map
//# sourceMappingURL=chunk-CJYFSKH7.js.map