"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TOKEN_TYPES = exports.SECONDS = void 0;
var SECONDS;
(function (SECONDS) {
    SECONDS[SECONDS["hour"] = 3600] = "hour";
    SECONDS[SECONDS["day"] = 86400] = "day";
    SECONDS[SECONDS["week"] = 604800] = "week";
})(SECONDS = exports.SECONDS || (exports.SECONDS = {}));
var TOKEN_TYPES;
(function (TOKEN_TYPES) {
    TOKEN_TYPES["access"] = "access_token";
    TOKEN_TYPES["refresh"] = "refresh_token";
})(TOKEN_TYPES = exports.TOKEN_TYPES || (exports.TOKEN_TYPES = {}));
