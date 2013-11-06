#include "Crypto/CryptoRandom.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/Integer.hpp"

#include "AuthenticationContext.hpp"

namespace Dissent {
namespace Crypto {
namespace DAGA {

  static Integer
  ComputeSharedSecret(QByteArray seed)
  {
    Hash h;
    h.Update(seed);
    Integer res = Integer(h.ComputeHash());
    // Make Q does not divide res. This loop will almost surely not run.
    while ((res %= AuthenticationContext::GetSubgroupSize()) == 0)
      res += 1;
    return res;
  }


  void AuthenticationContext::BeginClientAuth(ClientAuthenticationState &state) const
  {
    const Integer G = GetGenerator();
    const Integer P = GetModulus();
    const Integer Q = GetSubgroupSize();

    Hash h;
    Integer last_commitment = G, linkage_tag(m_generators[state.m_id]);
    state.m_secret_product = 1;
    for (int i = 0; i < m_server_public_keys.size(); i++) {
      Integer server_key = m_server_public_keys[i]->GetPublicElement();
      Integer seed = server_key.Pow(state.ephemeral_key.GetPrivateExponent(), P);
      Integer shared_secret = ComputeSharedSecret(seed.GetByteArray());
      state.m_secret_product = state.m_secret_product.Multiply(shared_secret, Q);
      last_commitment = last_commitment.Pow(shared_secret, P);
      state.commitments.append(last_commitment);
      linkage_tag = linkage_tag.Pow(shared_secret, P);
    }
    state.initial_linkage_tag = linkage_tag;

    CryptoRandom rand;

    // Begin client interactive proof.
    for (int i = 0; i < m_client_public_keys.size(); i++) {
      Integer client_public = m_client_public_keys[i]->GetPublicElement();
      Integer wi;
      if (i != state.m_id)
        wi = rand.GetInteger(0, Q);
      state.m_w.append(wi);
      Integer v0 = rand.GetInteger(0, Q);
      Integer v1 = rand.GetInteger(0, Q);
      state.m_v0.append(v0);
      state.m_v1.append(v1);
      Integer T00 = P.PowCascade(client_public, wi, G, v0);
      Integer T10 = P.PowCascade(last_commitment, wi, G, v1);
      Integer T11 = P.PowCascade(linkage_tag, wi, m_generators[i], v1);
      state.T00.append(T00);
      state.T10.append(T10);
      state.T11.append(T11);
    }
  }

  void AuthenticationContext::AnswerChallenge(ClientProof &proof,
                                              const ClientAuthenticationState &state,
                                              Integer challenge) const
  {
    const Integer Q = GetSubgroupSize();

    Integer sum;
    for (int i = 0; i < state.m_w.size(); i++) {
      challenge -= state.m_w[i];
      challenge = challenge % Q;
    }
    proof.C = state.m_w;
    proof.C[state.m_id] = challenge % Q;
    proof.R0 = state.m_v0;
    proof.R1 = state.m_v1;
    proof.R0[state.m_id] = (state.m_v0[state.m_id] - proof.C[state.m_id].Multiply(state.m_private_key->GetPrivateExponent(), Q)) % Q;
    proof.R1[state.m_id] = (state.m_v1[state.m_id] - proof.C[state.m_id].Multiply(state.m_secret_product, Q)) % Q;
  }

  VerificationResult AuthenticationContext::ProcessClientAuth(ServerVerificationState &state,
                                                              DishonestClientProof *dcp) const
  {
    const Integer P = GetModulus();
    const Integer G = GetGenerator();
    const Integer Q = GetSubgroupSize();

    CryptoRandom rand;

    // Check client proof.
    for (int i = 0; i < m_client_public_keys.size(); i++) {
      Integer client_public = m_client_public_keys[i]->GetPublicElement();
      Integer ci = state.client_proof.C[i];
      Integer R0 = state.client_proof.R0[i];
      Integer R1 = state.client_proof.R1[i];
      Integer T00 = state.T00[i];
      Integer T10 = state.T10[i];
      Integer T11 = state.T11[i];
      if (T00 != P.PowCascade(client_public, ci, G, R0))
        return VerificationResult::INVALID_CLIENT_PROOF;
      if (T10 != P.PowCascade(state.client_commitments.last(), ci, G, R1))
        return VerificationResult::INVALID_CLIENT_PROOF;
      if (T11 != P.PowCascade(state.initial_linkage_tag, ci, m_generators[i], R1))
        return VerificationResult::INVALID_CLIENT_PROOF;
    }
    Integer sum;
    for (int i = 0; i < state.client_proof.C.size(); i++) {
      sum += state.client_proof.C[i];
      sum %= Q;
    }
    if (sum != state.challenge)
      return VerificationResult::INVALID_CLIENT_PROOF;

    // Check other server proofs.
    for (int i = 0; i < state.server_proofs.size(); i++) {
      const ServerProof &proof = state.server_proofs.at(i);
      Integer previous_tag = (i > 0) ? state.server_proofs.at(i - 1).tag : state.initial_linkage_tag;
      Integer t1 = P.PowCascade(previous_tag, proof.r1, proof.tag, Q - proof.r2);
      Integer t2 = P.PowCascade(G, proof.r1, m_server_randomness[i], proof.c);
      Integer prev_commitment = (i > 0) ? state.client_commitments[i - 1] : G;
      Integer t3 = P.PowCascade(prev_commitment, proof.r2, state.client_commitments[i], proof.c);
      Hash h;
      h.Update(previous_tag.GetByteArray());
      h.Update(proof.tag.GetByteArray());
      h.Update(m_server_randomness[i].GetByteArray());
      h.Update(G.GetByteArray());
      h.Update(state.client_commitments[i].GetByteArray());
      h.Update(prev_commitment.GetByteArray());
      h.Update(t1.GetByteArray());
      h.Update(t2.GetByteArray());
      h.Update(t3.GetByteArray());
      if (Integer(h.ComputeHash()) != proof.c) {
        return VerificationResult::INVALID_SERVER_PROOF;
      }
    }

    // Check client commitment.
    Integer base = state.client_ephemeral_key.GetPublicElement();
    Integer shared_seed = base.Pow(state.server_private->GetPrivateExponent(), P);
    Integer shared_secret = ComputeSharedSecret(shared_seed.GetByteArray());
    Integer prev_commitment = (state.server_id > 0) ? state.client_commitments[state.server_id - 1] : G;
    if (prev_commitment.Pow(shared_secret, P) != state.client_commitments[state.server_id]) {
      if (dcp != nullptr) {
        // Prove the client was dishonest.
        dcp->server_id = state.server_id;
        dcp->shared_secret = shared_secret;
        dcp->client_ephemeral_key = state.client_ephemeral_key;
        dcp->disclosed_seed = shared_seed;
        Integer v = rand.GetInteger(0, Q);
        dcp->t1 = base.Pow(v, P);
        dcp->t2 = G.Pow(v, P);
        Hash h;
        h.Update(dcp->disclosed_seed.GetByteArray());
        h.Update(base.GetByteArray());
        h.Update(m_server_public_keys[state.server_id]->GetPublicElement().GetByteArray());
        h.Update(G.GetByteArray());
        h.Update(dcp->t1.GetByteArray());
        h.Update(dcp->t2.GetByteArray());
        dcp->c = Integer(h.ComputeHash());
        dcp->r = (v - dcp->c.Multiply(state.server_private->GetPrivateExponent(), Q)) % Q;
      }
      return VerificationResult::DISHONEST_CLIENT;
    }

    // Compute intermediate linkage tag and generate our server proof.
    ServerProof proof;
    Integer prev_tag = (state.server_id > 0) ? state.server_proofs.last().tag : state.initial_linkage_tag;
    Integer tag_exp = shared_secret.Inverse(Q).Multiply(state.private_randomness, Q);
    proof.tag = prev_tag.Pow(tag_exp, P);
    Integer v1 = rand.GetInteger(0, Q);
    Integer v2 = rand.GetInteger(0, Q);
    Integer t1 = P.PowCascade(prev_tag, v1, proof.tag, Q - v2);
    Integer t2 = G.Pow(v1, P);
    Integer t3 = prev_commitment.Pow(v2, P);
    Hash h;
    h.Update(prev_tag.GetByteArray());
    h.Update(proof.tag.GetByteArray());
    h.Update(m_server_randomness[state.server_id].GetByteArray());
    h.Update(G.GetByteArray());
    h.Update(state.client_commitments[state.server_id].GetByteArray());
    h.Update(prev_commitment.GetByteArray());
    h.Update(t1.GetByteArray());
    h.Update(t2.GetByteArray());
    h.Update(t3.GetByteArray());
    proof.c = Integer(h.ComputeHash());
    proof.r1 = (v1 - proof.c*state.private_randomness) % Q;
    proof.r2 = (v2 - proof.c*shared_secret) % Q;
    state.server_proofs.append(proof);

    bool done = state.server_id == m_server_public_keys.size() - 1;
    return (done) ? VerificationResult::SUCCESS : VerificationResult::CONTINUE;
  }

  bool AuthenticationContext::VerifyDishonestClientProof(const DishonestClientProof &proof) const
  {
    const Integer P = GetModulus();
    const Integer G = GetGenerator();

    Integer ephemeral_key = proof.client_ephemeral_key.GetPublicElement();
    Integer server_public = m_server_public_keys[proof.server_id]->GetPublicElement();
    Integer t1 = P.PowCascade(ephemeral_key, proof.r, proof.disclosed_seed, proof.c);
    Integer t2 = P.PowCascade(G, proof.r, server_public, proof.c);
    Hash h;
    h.Update(proof.disclosed_seed.GetByteArray());
    h.Update(ephemeral_key.GetByteArray());
    h.Update(server_public.GetByteArray());
    h.Update(G.GetByteArray());
    h.Update(t1.GetByteArray());
    h.Update(t2.GetByteArray());
    return Integer(h.ComputeHash()) == proof.c;
  }

}
}
}
