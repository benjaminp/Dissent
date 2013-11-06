#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Crypto, DAGA)
  {
    const int CLIENTS = 32;
    const int SERVERS = 3; // Needs to be at least 3 for the tests to work.
    const int CLIENT = 3;
    const Integer P = DAGA::AuthenticationContext::GetModulus();
    const Integer G = DAGA::AuthenticationContext::GetGenerator();
    const Integer Q = DAGA::AuthenticationContext::GetSubgroupSize();
    CryptoRandom rand;
    QList<QSharedPointer<DsaPublicKey> > client_keys;
    QList<QSharedPointer<DsaPublicKey> > server_keys;
    QList<Integer> server_private_randomness;
    QList<Integer> server_public_randomness;
    QList<Integer> generators;

    // Basic parameter sanity.
    ASSERT_EQ(G.Pow(Q, P), 1);

    for (int i = 0; i < CLIENTS; i++) {
      client_keys.append(QSharedPointer<DsaPublicKey>(new DsaPrivateKey(P, Q, G)));
      Integer gen;
      do {
        gen = rand.GetInteger(1 << (P.GetBitCount() - 1), P);
      } while (gen.Pow(2, P) == 1 || gen.Pow(Q, P) != 1);
      generators.append(gen);
    }
    for (int i = 0; i < SERVERS; i++) {
      server_keys.append(QSharedPointer<DsaPublicKey>(new DsaPrivateKey(P, Q, G)));
      server_private_randomness.append(rand.GetInteger(0, Q));
      server_public_randomness.append(G.Pow(server_private_randomness.last(), P));
    }

    DAGA::AuthenticationContext ac(client_keys,
                                   server_keys,
                                   server_public_randomness,
                                   generators);

    DAGA::ClientAuthenticationState cas(CLIENT, client_keys[CLIENT].staticCast<DsaPrivateKey>());
    DAGA::ClientProof client_proof;
    ac.BeginClientAuth(cas);
    Integer challenge = rand.GetInteger(0, Q);
    ac.AnswerChallenge(client_proof, cas, challenge);

    QList<DAGA::ServerProof> server_proofs;
    for (int i = 0; i < SERVERS; i++) {
      DAGA::ServerVerificationState svs(i, server_keys[i].staticCast<DsaPrivateKey>(),
                                        server_private_randomness[i],
                                        cas.ephemeral_key,
                                        cas.commitments,
                                        cas.initial_linkage_tag,
                                        cas.T00,
                                        cas.T10,
                                        cas.T11);
      svs.challenge = challenge;
      svs.client_proof = client_proof;
      svs.server_proofs = server_proofs;
      DAGA::VerificationResult expected = (i + 1 == SERVERS) ?
        DAGA::VerificationResult::SUCCESS :
        DAGA::VerificationResult::CONTINUE;
      EXPECT_EQ(ac.ProcessClientAuth(svs, nullptr), expected) << "Server " << i << " failed to validate.";
      server_proofs = svs.server_proofs;
    }

    Integer final_tag = server_proofs.last().tag;
    Integer s = 1;
    for (int i = 0; i < SERVERS; i++) {
      s = s.Multiply(server_private_randomness[i], Q);
    }
    EXPECT_EQ(final_tag, generators[CLIENT].Pow(s, P)) << "Linkage tag not correctly generated.";

    // Test dishonest client proofs.
    cas.commitments[1] = 42;
    server_proofs.clear();
    for (int i = 0; i < 2; i++) {
      DAGA::ServerVerificationState svs(i, server_keys[i].staticCast<DsaPrivateKey>(),
                                        server_private_randomness[i],
                                        cas.ephemeral_key,
                                        cas.commitments,
                                        cas.initial_linkage_tag,
                                        cas.T00,
                                        cas.T10,
                                        cas.T11);
      svs.challenge = challenge;
      svs.client_proof = client_proof;
      svs.server_proofs = server_proofs;
      DAGA::DishonestClientProof dcp;
      DAGA::VerificationResult expected = (i == 1) ?
        DAGA::VerificationResult::DISHONEST_CLIENT :
        DAGA::VerificationResult::CONTINUE;
      EXPECT_EQ(ac.ProcessClientAuth(svs, &dcp), expected) << "Server " << i << " failed to validate.";
      if (i == 1) {
        EXPECT_TRUE(ac.VerifyDishonestClientProof(dcp));
      }
      server_proofs = svs.server_proofs;
    }
  }

}
}
