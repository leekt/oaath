import {
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
} from "@oaath/protocol";
import type { OaathBindingInput } from "@oaath/sdk/advanced";

export const LOCAL_ISSUER = "https://local-fixture.example";
export const LOCAL_REDIRECT = "https://consumer.example/callback";

export function localClientBinding(
  owner: `0x${string}`,
  session: `0x${string}`,
): OaathBindingInput {
  const issuerUrl = LOCAL_ISSUER;
  const redirectUri = LOCAL_REDIRECT;
  return {
    issuer: issuerUrl,
    applicationId: "fixture-application",
    applicationName: "Local SDK Consumer",
    clientId: "fixture-client",
    origin: "https://consumer.example",
    redirectUri,
    deviceId: "fixture-device",
    userHandle: "fixture-user",
    context: {
      version: "oaath.workspace-account-context/v1",
      workspaceId: "fixture-workspace",
      workspaceKind: "personal",
      accountId: "fixture-account",
    },
    account: {
      version: OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
      kind: "kernel",
      accountIndex: "0",
      kernelVersion: "0.4.0",
      factoryRoute: "kernel_factory",
      entryPoint: { version: "0.7" },
      ownerCredential: {
        version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
        kind: "ecdsa",
        address: owner.toLowerCase(),
      },
    },
    operatorCredential: {
      version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
      kind: "ecdsa",
      address: session.toLowerCase(),
    },
  };
}
