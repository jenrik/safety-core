#!/usr/bin/env bun
import { replayHistoricalBashEvent, type HistoricalBashEvent } from "./opencode-history-adapter.ts";

const input = await Bun.stdin.text();
const events = JSON.parse(input) as unknown;
if (!Array.isArray(events)) throw new Error("Expected a JSON array of Bash events");

const results = [];
for (const event of events) {
  if (!event || typeof event !== "object") throw new Error("Each Bash event must be an object");
  results.push(await replayHistoricalBashEvent(event as HistoricalBashEvent));
}
console.log(JSON.stringify(results));
