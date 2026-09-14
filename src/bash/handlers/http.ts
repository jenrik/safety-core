import type { CommandHandler } from "../dispatch.js";
import { curlHandler } from "./command-curl.js";
import { fetchHandler } from "./command-fetch.js";
import { httpHandler } from "./command-http.js";
import { httpieHandler } from "./command-httpie.js";
import { httpxHandler } from "./command-httpx.js";
import { wgetHandler } from "./command-wget.js";

export const httpHandlers: readonly CommandHandler[] = Object.freeze([
  curlHandler,
  wgetHandler,
  httpHandler,
  httpieHandler,
  fetchHandler,
  httpxHandler,
]);
