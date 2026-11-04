"""
Verification tooling beside the execution layer specification.

The spec under `src/ethereum` is the thing verified and is never changed or
instrumented by this package. Each module here answers one question about
the spec, using the testing framework (`execution_testing`) as its
independent reference:

- `properties`: does a rule hold for every input, not only the ones a test
  writer chose?
"""
