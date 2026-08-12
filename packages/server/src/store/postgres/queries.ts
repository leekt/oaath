/**
 * Relay SQL. Text only: no state-machine decision lives in this file.
 *
 * Names are unqualified so a deployment (or a disposable test schema) selects
 * them with `search_path`.
 *
 * @author taek <leekt216@gmail.com>
 */

const REQUEST_COLUMNS = `
  request_id, record_version, client_id, subject, organization_audience,
  redirect_uri, code_challenge, requested_scope, created_at, expires_at
`;

const CODE_COLUMNS = `
  code_hash, record_version, request_id, client_id, redirect_uri,
  code_challenge, artifact_id, created_at, expires_at, consumed_at
`;

const ARTIFACT_COLUMNS = `
  artifact_id, record_version, request_id, client_id, ciphertext_ref,
  created_at, claimed_at
`;

export const LOCK_AUTHORIZATION_REQUEST = `
  SELECT ${REQUEST_COLUMNS}
  FROM oaath_relay_authorization_request_v1
  WHERE request_id = $1
  FOR UPDATE
`;

export const INSERT_AUTHORIZATION_REQUEST = `
  INSERT INTO oaath_relay_authorization_request_v1 (${REQUEST_COLUMNS})
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
  ON CONFLICT (request_id) DO NOTHING
`;

export const LOCK_AUTHORIZATION_DECISION = `
  SELECT request_id, record_version, outcome, decided_at, code_ref, code_expires_at
  FROM oaath_relay_authorization_decision_v1
  WHERE request_id = $1
  FOR UPDATE
`;

export const INSERT_AUTHORIZATION_DECISION = `
  INSERT INTO oaath_relay_authorization_decision_v1 (
    request_id, record_version, outcome, decided_at, code_ref, code_expires_at
  ) VALUES ($1, $2, $3, $4, $5, $6)
  ON CONFLICT (request_id) DO NOTHING
`;

export const LOCK_CAPABILITY_INVALIDATION = `
  SELECT grant_id, record_version, client_id, capability_hash, invalidated_at
  FROM oaath_relay_capability_invalidation_v1
  WHERE grant_id = $1
  FOR UPDATE
`;

export const INSERT_CAPABILITY_INVALIDATION = `
  INSERT INTO oaath_relay_capability_invalidation_v1 (
    grant_id, record_version, client_id, capability_hash, invalidated_at
  ) VALUES ($1, $2, $3, $4, $5)
  ON CONFLICT (grant_id) DO NOTHING
`;

export const LOCK_AUTHORIZATION_CODE = `
  SELECT ${CODE_COLUMNS}
  FROM oaath_relay_authorization_code_v1
  WHERE code_hash = $1
  FOR UPDATE
`;

export const INSERT_AUTHORIZATION_CODE = `
  INSERT INTO oaath_relay_authorization_code_v1 (${CODE_COLUMNS})
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
  ON CONFLICT DO NOTHING
`;

/** One-shot: the guard makes a second consume affect zero rows. */
export const CONSUME_AUTHORIZATION_CODE = `
  UPDATE oaath_relay_authorization_code_v1
  SET consumed_at = $2
  WHERE code_hash = $1 AND consumed_at IS NULL
`;

export const LOCK_ENCRYPTED_ARTIFACT = `
  SELECT ${ARTIFACT_COLUMNS}
  FROM oaath_relay_encrypted_artifact_v1
  WHERE artifact_id = $1
  FOR UPDATE
`;

export const INSERT_ENCRYPTED_ARTIFACT = `
  INSERT INTO oaath_relay_encrypted_artifact_v1 (${ARTIFACT_COLUMNS})
  VALUES ($1, $2, $3, $4, $5, $6, $7)
  ON CONFLICT DO NOTHING
`;

/** One-shot: the guard makes a second claim affect zero rows. */
export const CLAIM_ENCRYPTED_ARTIFACT = `
  UPDATE oaath_relay_encrypted_artifact_v1
  SET claimed_at = $2
  WHERE artifact_id = $1 AND claimed_at IS NULL
`;
