#!/usr/bin/env bun
import { replayHistoricalBashEvents, type HistoricalBashEvent } from "./opencode-history-adapter.ts";

const input = await Bun.stdin.text();
const events = JSON.parse(input) as unknown;
if (!Array.isArray(events)) throw new Error("Expected a JSON array of Bash events");

for (const event of events) {
  if (!event || typeof event !== "object") throw new Error("Each Bash event must be an object");
}
console.log(JSON.stringify(await replayHistoricalBashEvents(events as HistoricalBashEvent[])));
