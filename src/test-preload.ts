import { policyTestFromEnvironment } from "./policy/testing.js";

Object.defineProperty(globalThis, "policyTest", {
  value: policyTestFromEnvironment(),
  configurable: false,
  enumerable: false,
  writable: false,
});
