import type { PolicyObserver } from "../dispatch.js";
import { batHandler } from "./command-bat.js";
import { catHandler } from "./command-cat.js";
import { dotHandler } from "./command-dot.js";
import { headHandler } from "./command-head.js";
import { hexdumpHandler } from "./command-hexdump.js";
import { lessHandler } from "./command-less.js";
import { moreHandler } from "./command-more.js";
import { odHandler } from "./command-od.js";
import { sourceHandler } from "./command-source.js";
import { stringsHandler } from "./command-strings.js";
import { tailHandler } from "./command-tail.js";
import { viewHandler } from "./command-view.js";
import { xxdHandler } from "./command-xxd.js";

export const readerHandlers: readonly PolicyObserver[] = Object.freeze([
  catHandler,
  headHandler,
  tailHandler,
  lessHandler,
  batHandler,
  moreHandler,
  viewHandler,
  xxdHandler,
  odHandler,
  hexdumpHandler,
  stringsHandler,
  sourceHandler,
  dotHandler,
]);
