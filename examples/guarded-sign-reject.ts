import { readFileSync } from "node:fs";
import {
  SignBlockedError,
  guardedSignTransaction,
} from "../skill/src/adapters/index.ts";

const dangerousTransaction = readFileSync(
  new URL("../skill/fixtures/02_setauthority_reject.b64", import.meta.url),
  "utf8",
).trim();

let signerWasCalled = false;

try {
  await guardedSignTransaction(
    dangerousTransaction,
    async () => {
      signerWasCalled = true;
      return "signed";
    },
    {
      transactionToBase64: (transaction) => transaction,
      onHold: () => false,
    },
  );
} catch (err) {
  if (!(err instanceof SignBlockedError)) throw err;
  console.log("blocked before signing");
  console.log(`decision: ${err.verdict.decision}`);
  console.log(`signer called: ${signerWasCalled}`);
}
