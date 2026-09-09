import type { RelayCaller, ServiceDirectoryDocument } from "../src/index.js";
import { APPROVABLE_PERMISSION_SCOPE } from "./support.js";

export function permissionScope(workspaceId = "personal-1"): string {
  const document = directoryDocument();
  const account = document.accounts.find((entry) => entry.workspaceId === workspaceId)!;
  const workspace = document.workspaces.find((entry) => entry.workspaceId === workspaceId)!;
  const scope = JSON.parse(APPROVABLE_PERMISSION_SCOPE);
  return JSON.stringify({
    ...scope,
    context: {
      version: "oaath.workspace-account-context/v1",
      workspaceId,
      workspaceKind: workspace.kind,
      accountId: account.accountId,
    },
    application: { ...scope.application, applicationId: "app-a" },
    logicalAccount: account.account,
  });
}

export function member(subject: string): RelayCaller {
  return {
    role: "client",
    clientId: "client-a",
    subject,
    redirectUris: ["https://app.example/callback"],
    organizationAudience: null,
  };
}

export function directoryDocument(): ServiceDirectoryDocument {
  const account = {
    version: "oaath.kernel-account-profile/v1" as const,
    kind: "kernel" as const,
    accountIndex: "0",
    kernelVersion: "0.4.0" as const,
    factoryRoute: "kernel_factory" as const,
    entryPoint: { version: "0.7" as const },
    ownerCredential: {
      version: "oaath.owner-credential-profile/v1" as const,
      kind: "ecdsa" as const,
      address: `0x${"11".repeat(20)}` as `0x${string}`,
    },
  };
  return {
    version: "oaath.service-directory/v1",
    applications: [{ clientId: "client-a", applicationId: "app-a", applicationName: "Example" }],
    workspaces: [
      { workspaceId: "personal-1", kind: "personal" },
      { workspaceId: "team-1", kind: "team" },
    ],
    memberships: [
      { workspaceId: "personal-1", clientId: "client-a", subject: "subject-1" },
      { workspaceId: "team-1", clientId: "client-a", subject: "subject-1" },
      { workspaceId: "team-1", clientId: "client-a", subject: "subject-2" },
    ],
    ownerDevices: [
      { workspaceId: "personal-1", ownerDeviceId: "phone-1", subject: "phone-subject-1" },
      { workspaceId: "team-1", ownerDeviceId: "phone-2", subject: "phone-subject-2" },
    ],
    accounts: [
      {
        workspaceId: "personal-1",
        accountId: "account-1",
        ownerDeviceId: "phone-1",
        account,
        ownerValidator: `0x${"22".repeat(20)}`,
        chainIds: [31_337],
      },
      {
        workspaceId: "team-1",
        accountId: "treasury",
        ownerDeviceId: "phone-2",
        account: { ...structuredClone(account), accountIndex: "1" },
        ownerValidator: `0x${"22".repeat(20)}`,
        chainIds: [31_337],
      },
    ],
    selections: [
      {
        clientId: "client-a",
        subject: "subject-1",
        workspaceId: "personal-1",
        accountId: "account-1",
      },
      { clientId: "client-a", subject: "subject-2", workspaceId: "team-1", accountId: "treasury" },
    ],
  };
}
