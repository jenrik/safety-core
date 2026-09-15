import type { PolicyObserver } from "../dispatch.js";
import { allow, defer, hasUnsafeGitArgument, readOnlyHandler } from "./read-only-utils.js";

// The user treats committed Git data and the repository's configured diff
// pipeline as trusted. Keep this narrow to built-in inspection commands and
// reject options that can write, inspect arbitrary filesystem paths, or force
// external conversion where it is not otherwise the default.
export const gitReadOnlyHandler: PolicyObserver = readOnlyHandler("git", "generic-read-only", (args) => {
  const subcommand = args[0];
  if (!subcommand || !["show", "diff"].includes(subcommand) || hasUnsafeGitArgument(args.slice(1))) {
    return defer("generic-read-only", "git");
  }
  return allow("generic-read-only", "git");
});
