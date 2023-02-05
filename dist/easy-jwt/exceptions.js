"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EasyJWTGetModelError = exports.EasyJWTSubjectError = exports.EasyJWTTypeError = exports.EasyJWTValidationError = void 0;
class BaseError extends Error {
}
class EasyJWTValidationError extends BaseError {
}
exports.EasyJWTValidationError = EasyJWTValidationError;
class EasyJWTTypeError extends BaseError {
}
exports.EasyJWTTypeError = EasyJWTTypeError;
class EasyJWTSubjectError extends BaseError {
}
exports.EasyJWTSubjectError = EasyJWTSubjectError;
class EasyJWTGetModelError extends BaseError {
}
exports.EasyJWTGetModelError = EasyJWTGetModelError;
