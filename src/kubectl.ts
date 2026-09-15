// kubectl-specific policy compatibility adapters backed by the Bash walker.
// TODO: Remove these repeated whole-command compatibility evaluations once the
// configured core evaluator exposes structured kubectl verdict and audit data.

import {
  isProtectedKubectlResource,
  kubectlResourceOperandsRequireReview,
  kubectlResourceType,
} from "./bash/policies/kubectl.js";

export { isProtectedKubectlResource, kubectlResourceOperandsRequireReview, kubectlResourceType };
