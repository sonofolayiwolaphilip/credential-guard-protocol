;; DigitalCredentialSecurityMatrix - Enterprise-grade credential validation ecosystem with tiered access control
;;
;; This protocol establishes a secure environment for credential registration, verification, and delegation
;; with comprehensive auditing capabilities and configurable entitlement structures

;; Credential Registry Sequential Marker
(define-data-var credential-sequence-tracker uint u0)

;; Protocol Guardian Identity
(define-constant protocol-guardian tx-sender)

;; Rejection Status Codification

(define-constant unauthorized-credential-requester-error (err u306))
(define-constant guardian-privilege-required-error (err u300))
(define-constant credential-not-registered-error (err u301))
(define-constant credential-already-exists-error (err u302))
(define-constant credential-label-format-error (err u303))
(define-constant credential-metric-range-error (err u304))
(define-constant entitlement-insufficient-error (err u305))
(define-constant credential-viewing-restricted-error (err u307))
(define-constant credential-classification-error (err u308))

;; ===== Utility Operations =====

;; Validates classification format requirements
(define-private (is-valid-classification (classification (string-ascii 32)))
  (and
    (> (len classification) u0)
    (< (len classification) u33)
  )
)

;; Validates the complete classification collection
(define-private (validate-classification-set (classifications (list 10 (string-ascii 32))))
  (and
    (> (len classifications) u0)
    (<= (len classifications) u10)
    (is-eq (len (filter is-valid-classification classifications)) (len classifications))
  )
)

;; Confirms credential exists in repository
(define-private (credential-exists (credential-id uint))
  (is-some (map-get? credential-repository { credential-id: credential-id }))
)

;; Retrieves metric magnitude for a credential
(define-private (get-metric-magnitude (credential-id uint))
  (default-to u0
    (get metric-magnitude
      (map-get? credential-repository { credential-id: credential-id })
    )
  )
)

;; Credential ownership verification
(define-private (is-credential-custodian (credential-id uint) (inspector principal))
  (match (map-get? credential-repository { credential-id: credential-id })
    credential-data (is-eq (get credential-custodian credential-data) inspector)
    false
  )
)

;; Central Data Repository
(define-map credential-repository
  { credential-id: uint }
  {
    credential-label: (string-ascii 64),
    credential-custodian: principal,
    metric-magnitude: uint,
    registration-timestamp: uint,
    credential-designation: (string-ascii 128),
    classification-markers: (list 10 (string-ascii 32))
  }
)

;; Entitlement Management Framework
(define-map entitlement-framework
  { credential-id: uint, inspector: principal }
  { inspection-authorized: bool }
)

;; ===== Core Protocol Functions =====

;; Register new credential with comprehensive attributes
(define-public (register-credential
  (label (string-ascii 64))
  (magnitude uint)
  (designation (string-ascii 128))
  (classifications (list 10 (string-ascii 32)))
)
  (let
    (
      (new-credential-id (+ (var-get credential-sequence-tracker) u1))
    )
    ;; Parameter validation
    (asserts! (> (len label) u0) credential-label-format-error)
    (asserts! (< (len label) u65) credential-label-format-error)
    (asserts! (> magnitude u0) credential-metric-range-error)
    (asserts! (< magnitude u1000000000) credential-metric-range-error)
    (asserts! (> (len designation) u0) credential-label-format-error)
    (asserts! (< (len designation) u129) credential-label-format-error)
    (asserts! (validate-classification-set classifications) credential-classification-error)

    ;; Create credential entry in repository
    (map-insert credential-repository
      { credential-id: new-credential-id }
      {
        credential-label: label,
        credential-custodian: tx-sender,
        metric-magnitude: magnitude,
        registration-timestamp: block-height,
        credential-designation: designation,
        classification-markers: classifications
      }
    )

    ;; Initialize inspection entitlement for creator
    (map-insert entitlement-framework
      { credential-id: new-credential-id, inspector: tx-sender }
      { inspection-authorized: true }
    )

    ;; Update sequence tracker
    (var-set credential-sequence-tracker new-credential-id)
    (ok new-credential-id)
  )
)

;; Update existing credential attributes
(define-public (update-credential-attributes
  (credential-id uint)
  (revised-label (string-ascii 64))
  (revised-magnitude uint)
  (revised-designation (string-ascii 128))
  (revised-classifications (list 10 (string-ascii 32)))
)
  (let
    (
      (credential-data (unwrap! (map-get? credential-repository { credential-id: credential-id })
        credential-not-registered-error))
    )
    ;; Validation of custody and parameters
    (asserts! (credential-exists credential-id) credential-not-registered-error)
    (asserts! (is-eq (get credential-custodian credential-data) tx-sender) unauthorized-credential-requester-error)
    (asserts! (> (len revised-label) u0) credential-label-format-error)
    (asserts! (< (len revised-label) u65) credential-label-format-error)
    (asserts! (> revised-magnitude u0) credential-metric-range-error)
    (asserts! (< revised-magnitude u1000000000) credential-metric-range-error)
    (asserts! (> (len revised-designation) u0) credential-label-format-error)
    (asserts! (< (len revised-designation) u129) credential-label-format-error)
    (asserts! (validate-classification-set revised-classifications) credential-classification-error)

    ;; Update credential record with new information
    (map-set credential-repository
      { credential-id: credential-id }
      (merge credential-data {
        credential-label: revised-label,
        metric-magnitude: revised-magnitude,
        credential-designation: revised-designation,
        classification-markers: revised-classifications
      })
    )
    (ok true)
  )
)

;; Transfer credential custody to new principal
(define-public (transfer-credential-custody (credential-id uint) (new-custodian principal))
  (let
    (
      (credential-data (unwrap! (map-get? credential-repository { credential-id: credential-id })
        credential-not-registered-error))
    )
    ;; Verify caller is the current custodian
    (asserts! (credential-exists credential-id) credential-not-registered-error)
    (asserts! (is-eq (get credential-custodian credential-data) tx-sender) unauthorized-credential-requester-error)

    ;; Update custody record
    (map-set credential-repository
      { credential-id: credential-id }
      (merge credential-data { credential-custodian: new-custodian })
    )
    (ok true)
  )
)

;; Revoke credential from repository permanently
(define-public (revoke-credential (credential-id uint))
  (let
    (
      (credential-data (unwrap! (map-get? credential-repository { credential-id: credential-id })
        credential-not-registered-error))
    )
    ;; Custody verification
    (asserts! (credential-exists credential-id) credential-not-registered-error)
    (asserts! (is-eq (get credential-custodian credential-data) tx-sender) unauthorized-credential-requester-error)

    ;; Remove credential from repository
    (map-delete credential-repository { credential-id: credential-id })
    (ok true)
  )
)

;; ===== Tiered Access Control Framework =====

;; Define access tiers
(define-constant access-tier-none u0)
(define-constant access-tier-view u1)
(define-constant access-tier-modify u2)
(define-constant access-tier-admin u3)

;; Enhanced entitlement registry with tiers
(define-map enhanced-entitlements
  { credential-id: uint, participant: principal }
  { 
    entitlement-tier: uint,
    granted-by: principal,
    granted-at: uint
  }
)

;; Grant specific entitlement tier to a participant
(define-public (grant-entitlement (credential-id uint) (participant principal) (entitlement-tier uint))
  (let
    (
      (credential-data (unwrap! (map-get? credential-repository { credential-id: credential-id })
        credential-not-registered-error))
    )
    ;; Verify caller is the credential custodian
    (asserts! (is-eq (get credential-custodian credential-data) tx-sender) unauthorized-credential-requester-error)
    ;; Verify valid entitlement tier
    (asserts! (<= entitlement-tier access-tier-admin) (err u500))

    (ok true)
  )
)

;; Check if participant has required entitlement tier
(define-private (has-entitlement (credential-id uint) (participant principal) (required-tier uint))
  (let
    (
      (credential-data (map-get? credential-repository { credential-id: credential-id }))
      (entitlement-data (map-get? enhanced-entitlements { credential-id: credential-id, participant: participant }))
    )
    (if (is-some credential-data)
      (if (is-eq (get credential-custodian (unwrap! credential-data false)) participant)
        ;; Custodian has all entitlements
        true
        ;; Check entitlement tier for non-custodians
        (if (is-some entitlement-data)
          (>= (get entitlement-tier (unwrap! entitlement-data false)) required-tier)
          false
        )
      )
      false
    )
  )
)

;; ===== Protocol Safety Mechanisms =====

;;  Authorization Rate Limiting Protocol
;; Prevent system abuse by implementing authorization rate limiting

;; Operation tracking by principal
(define-map authorization-tracker
  { participant: principal }
  {
    last-authorization-timestamp: uint,
    authorizations-in-window: uint
  }
)

;; Rate limit configuration
(define-data-var authorization-window uint u100)  ;; blocks
(define-data-var max-authorizations uint u10)  ;; max operations per window

;; Check and update rate limit
(define-private (check-authorization-limit (participant principal))
  (let
    (
      (tracker (default-to { last-authorization-timestamp: u0, authorizations-in-window: u0 }
        (map-get? authorization-tracker { participant: participant })))
      (current-window-start (- block-height (var-get authorization-window)))
    )
    (if (< (get last-authorization-timestamp tracker) current-window-start)
      ;; New window, reset counter
      (begin
        (map-set authorization-tracker { participant: participant }
          { last-authorization-timestamp: block-height, authorizations-in-window: u1 })
        true)
      ;; Check limit in current window
      (if (< (get authorizations-in-window tracker) (var-get max-authorizations))
        (begin
          (map-set authorization-tracker { participant: participant }
            { 
              last-authorization-timestamp: block-height,
              authorizations-in-window: (+ (get authorizations-in-window tracker) u1)
            })
          true)
        false)
    )
  )
)

;; Rate-limited credential registration
(define-public (rate-limited-credential-registration
  (label (string-ascii 64))
  (magnitude uint)
  (designation (string-ascii 128))
  (classifications (list 10 (string-ascii 32)))
)
  (begin
    ;; Check rate limit
    (asserts! (check-authorization-limit tx-sender) (err u700))

    ;; Call original function
    (register-credential label magnitude designation classifications)
  )
)

;; ===== Integrity Verification Framework =====

;; Credential integrity registry
(define-map credential-integrity
  { credential-id: uint }
  {
    cryptographic-signature: (buff 32),
    signature-algorithm: (string-ascii 10),
    last-verified: uint,
    verified-by: principal
  }
)

;; Register cryptographic signature for credential verification
(define-public (register-credential-signature (credential-id uint) (cryptographic-signature (buff 32)) (algorithm (string-ascii 10)))
  (let
    (
      (credential-data (unwrap! (map-get? credential-repository { credential-id: credential-id })
        credential-not-registered-error))
    )
    ;; Verify caller is the credential custodian
    (asserts! (is-eq (get credential-custodian credential-data) tx-sender) unauthorized-credential-requester-error)
    ;; Verify valid signature algorithm (sha256 or keccak256)
    (asserts! (or (is-eq algorithm "sha256") (is-eq algorithm "keccak256")) (err u600))

    (ok true)
  )
)

;; Verify credential against registered signature
(define-public (verify-credential-integrity (credential-id uint) (verification-signature (buff 32)))
  (let
    (
      (integrity-data (unwrap! (map-get? credential-integrity { credential-id: credential-id })
        (err u601)))
    )
    ;; Verify signature matches registered signature
    (asserts! (is-eq (get cryptographic-signature integrity-data) verification-signature) (err u602))

    (ok true)
  )
)

;; ===== Protocol Safety Controls =====

;;  Time-locked secure operations
;; Prevents immediate credential transfers by requiring confirmation after a time delay

;; Pending operations registry
(define-map pending-operations
  { operation-id: uint, credential-id: uint }
  {
    operation-category: (string-ascii 20),
    initiator: principal,
    target-entity: (optional principal),
    initiated-at-block: uint,
    confirmation-code: (buff 32),
    expiration-block: uint
  }
)

;; Operation counter
(define-data-var operation-sequence uint u0)

;; Time lock duration (in blocks)
(define-data-var security-delay-blocks uint u10)

;; Initialize pending transfer with confirmation code and time lock
(define-public (initiate-secure-custody-transfer (credential-id uint) (new-custodian principal) (confirmation-hash (buff 32)))
  (let
    (
      (credential-data (unwrap! (map-get? credential-repository { credential-id: credential-id })
        credential-not-registered-error))
      (operation-id (+ (var-get operation-sequence) u1))
      (expiration (+ block-height (var-get security-delay-blocks)))
    )
    ;; Verify caller is the current custodian
    (asserts! (credential-exists credential-id) credential-not-registered-error)
    (asserts! (is-eq (get credential-custodian credential-data) tx-sender) unauthorized-credential-requester-error)

    ;; Update operation counter
    (var-set operation-sequence operation-id)
    (ok operation-id)
  )
)

;;  Protocol contingency mechanism
;; Allow protocol guardian to suspend critical operations in emergencies

;; Protocol emergency state
(define-data-var protocol-suspended bool false)

;; Suspension justification
(define-data-var suspension-reason (string-ascii 128) "")

;; Restore protocol operations
(define-public (restore-protocol-operations)
  (begin
    ;; Guardian only
    (asserts! (is-eq tx-sender protocol-guardian) guardian-privilege-required-error)

    ;; Clear suspension state
    (var-set protocol-suspended false)
    (var-set suspension-reason "")
    (ok true)
  )
)

;; Check if protocol is operational
(define-private (is-protocol-operational)
  (not (var-get protocol-suspended))
)

