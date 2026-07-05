package config

import "fmt"

// Predefined IKE/IPsec proposal-set expansion (fable-167 V-1, #4297).
//
// Junos `security ike policy P proposal-set <set>` and
// `security ipsec policy P proposal-set <set>` are the standard shorthand
// operators use to avoid hand-defining proposals. Each named set expands to
// a fixed list of concrete proposals. Before this change the keyword was
// silently dropped by the compiler switch (unknown keys are ignored), so the
// policy resolved to NO proposal: the IPsec side hard-rejected with a
// misleading "no resolvable ipsec proposal" message and the IKE side left the
// chain unresolved (errIKEChainUnresolved) — either way the common vSRX idiom
// could not commit a working tunnel.
//
// The tables below are the single source of truth. They use Junos algorithm
// spellings; the pkg/ipsec renderer normalizes them to swanctl tokens
// (buildIKEProposalFromIKE / buildESPProposal) so the expansion needs no
// crypto knowledge here — it only names the members. Keeping the members in
// one explicit, tested table (rather than a hidden default substitution) is
// deliberate: the crypto is auditable and correctable, never fabricated.
//
// Members follow Juniper's published predefined-proposal tables:
//   - basic / compatible / standard: legacy DES/3DES/SHA1/MD5 sets, DH
//     group 2. These are weak by modern standards and a hardened strongSwan
//     build may not have the `des` plugin loaded; the operator asked for the
//     legacy set, so we expand it faithfully rather than silently upgrading.
//   - suiteb-gcm-128 / suiteb-gcm-256: RFC 6379 Suite-B — AES-GCM AEAD with
//     ECDSA authentication and an ECP (elliptic-curve) DH group. suiteb
//     requires ECDSA certificates (authMethodToSwan maps ecdsa-signatures to
//     pubkey); that is the operator's responsibility, exactly as on Junos.

// ikeProposalSetSpec is one Phase-1 proposal member of a predefined set.
type ikeProposalSetSpec struct {
	authMethod string // Junos authentication-method (pre-shared-keys / ecdsa-signatures)
	enc        string // Junos encryption-algorithm
	auth       string // Junos authentication-algorithm (also the AEAD PRF hint)
	dhGroup    int    // Diffie-Hellman group number
}

// espProposalSetSpec is one Phase-2 (ESP) proposal member of a predefined set.
type espProposalSetSpec struct {
	enc     string // Junos encryption-algorithm
	auth    string // Junos authentication-algorithm ("" for AEAD/GCM)
	dhGroup int    // PFS DH group carried on the proposal (0 = no PFS)
}

// ikeProposalSets maps a Junos IKE proposal-set keyword to its member
// proposals, in negotiation-preference order.
var ikeProposalSets = map[string][]ikeProposalSetSpec{
	"basic": {
		{"pre-shared-keys", "des-cbc", "sha1", 2},
		{"pre-shared-keys", "des-cbc", "md5", 2},
	},
	"compatible": {
		{"pre-shared-keys", "3des-cbc", "sha1", 2},
		{"pre-shared-keys", "3des-cbc", "md5", 2},
		{"pre-shared-keys", "des-cbc", "sha1", 2},
		{"pre-shared-keys", "des-cbc", "md5", 2},
	},
	"standard": {
		{"pre-shared-keys", "3des-cbc", "sha1", 2},
		{"pre-shared-keys", "aes-128-cbc", "sha1", 2},
	},
	"suiteb-gcm-128": {
		{"ecdsa-signatures", "aes-128-gcm", "sha-256", 19},
	},
	"suiteb-gcm-256": {
		{"ecdsa-signatures", "aes-256-gcm", "sha-384", 20},
	},
}

// espProposalSets maps a Junos IPsec proposal-set keyword to its member ESP
// proposals. The legacy sets carry no PFS (group at policy level in Junos is
// separate); the suiteb sets carry their Suite-B ECP group as the proposal's
// PFS group so buildESPProposal renders the ecp<N> term.
var espProposalSets = map[string][]espProposalSetSpec{
	"basic": {
		{"des-cbc", "hmac-sha1-96", 0},
		{"des-cbc", "hmac-md5-96", 0},
	},
	"compatible": {
		{"3des-cbc", "hmac-sha1-96", 0},
		{"3des-cbc", "hmac-md5-96", 0},
		{"des-cbc", "hmac-sha1-96", 0},
		{"des-cbc", "hmac-md5-96", 0},
	},
	"standard": {
		{"3des-cbc", "hmac-sha1-96", 0},
		{"aes-128-cbc", "hmac-sha1-96", 0},
	},
	"suiteb-gcm-128": {
		{"aes-128-gcm", "", 19},
	},
	"suiteb-gcm-256": {
		{"aes-256-gcm", "", 20},
	},
}

// ProposalSetNames returns the supported predefined proposal-set keywords
// (sorted, stable) for schema enum validation and completion.
func ProposalSetNames() []string {
	return []string{"basic", "compatible", "standard", "suiteb-gcm-128", "suiteb-gcm-256"}
}

// syntheticProposalSetName builds a deterministic, collision-resistant name
// for a proposal synthesized from a policy's proposal-set. The rendered
// swanctl proposal is the crypto token string (buildIKEProposalFromIKE /
// buildESPProposal), not this name, so the name is internal only; the "__"
// prefix and slashes keep it clear of operator-authored proposal names.
func syntheticProposalSetName(policy, set string, n int) string {
	return fmt.Sprintf("__proposal-set/%s/%s/%d", policy, set, n)
}

// expandIKEProposalSets synthesizes concrete IKE (Phase 1) proposals for every
// IKE policy that carries a `proposal-set`, appending them to the IKE proposal
// map and pointing the policy's Proposals list at them. It runs after the IKE
// proposal and policy loops so both maps exist. A policy that ALSO lists
// explicit `proposals` keeps them (proposal-set is the no-explicit-proposals
// shorthand and is mutually exclusive with `proposals` in Junos); the set only
// fills an empty list. An unknown set keyword is left unexpanded — the schema
// enum validator rejects it at commit.
func expandIKEProposalSets(sec *SecurityConfig) {
	if sec == nil || sec.IPsec.IKEPolicies == nil {
		return
	}
	if sec.IPsec.IKEProposals == nil {
		sec.IPsec.IKEProposals = make(map[string]*IKEProposal)
	}
	for _, pol := range sec.IPsec.IKEPolicies {
		if pol == nil || pol.ProposalSet == "" || len(pol.Proposals) > 0 {
			continue
		}
		specs, ok := ikeProposalSets[pol.ProposalSet]
		if !ok {
			continue
		}
		for i, s := range specs {
			name := syntheticProposalSetName(pol.Name, pol.ProposalSet, i+1)
			sec.IPsec.IKEProposals[name] = &IKEProposal{
				Name:          name,
				AuthMethod:    s.authMethod,
				EncryptionAlg: s.enc,
				AuthAlg:       s.auth,
				DHGroup:       s.dhGroup,
			}
			pol.Proposals = append(pol.Proposals, name)
		}
	}
}

// expandIPsecProposalSets is the Phase-2 (ESP) mirror of
// expandIKEProposalSets.
func expandIPsecProposalSets(sec *SecurityConfig) {
	if sec == nil || sec.IPsec.Policies == nil {
		return
	}
	if sec.IPsec.Proposals == nil {
		sec.IPsec.Proposals = make(map[string]*IPsecProposal)
	}
	for _, pol := range sec.IPsec.Policies {
		if pol == nil || pol.ProposalSet == "" || len(pol.Proposals) > 0 {
			continue
		}
		specs, ok := espProposalSets[pol.ProposalSet]
		if !ok {
			continue
		}
		for i, s := range specs {
			name := syntheticProposalSetName(pol.Name, pol.ProposalSet, i+1)
			sec.IPsec.Proposals[name] = &IPsecProposal{
				Name:          name,
				Protocol:      "esp",
				EncryptionAlg: s.enc,
				AuthAlg:       s.auth,
				DHGroup:       s.dhGroup,
			}
			pol.Proposals = append(pol.Proposals, name)
		}
	}
}
