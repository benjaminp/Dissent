#ifndef DISSENT_CRYPTO_DAGA_AUTHENTICATIONCONTEXT_GUARD
#define DISSENT_CRYPTO_DAGA_AUTHENTICATIONCONTEXT_GUARD

#include <QList>

#include "Crypto/DsaPublicKey.hpp"
#include "Crypto/DsaPrivateKey.hpp"
#include "Crypto/Integer.hpp"

namespace Dissent {
namespace Crypto {
namespace DAGA {

  struct ClientAuthenticationState;
  struct ClientProof;
  struct ServerVerificationState;
  struct DishonestClientProof;

  enum class VerificationResult {
    SUCCESS,
    CONTINUE,
    INVALID_CLIENT_PROOF,
    DISHONEST_CLIENT,
    INVALID_SERVER_PROOF
  };

  class AuthenticationContext {

    public:
      AuthenticationContext(const QList<QSharedPointer<DsaPublicKey>> client_public_keys,
                            const QList<QSharedPointer<DsaPublicKey>> server_public_keys,
                            const QList<Integer> server_randomness,
                            const QList<Integer> generators)
        : m_client_public_keys(client_public_keys),
          m_server_public_keys(server_public_keys),
          m_server_randomness(server_randomness),
          m_generators(generators)
      {}

      void BeginClientAuth(ClientAuthenticationState &) const;

      void AnswerChallenge(ClientProof &, const ClientAuthenticationState &, Integer) const;

      bool VerifyDishonestClientProof(const DishonestClientProof &) const;

      /*
       * Server endpoint.
       */
      VerificationResult ProcessClientAuth(ServerVerificationState &, DishonestClientProof *) const;

      QList<QSharedPointer<DsaPublicKey>> GetServerPublicKeys() const {
        return m_server_public_keys;
      }

      static Integer GetModulus()
      {
        static Integer p(QByteArray::fromHex("0xdd3ad12eb1ee09bcea5933d8434e44ea21f95114eb92493ce9b057ddb2a3c22d4a96daf1a785adec4807d4347b745f773e1aaf1b2b98789cd745536dbfe7fa8d2ffde100a428addd3b050ddbb5f23f1aebcdb324026672c3f34122f41f6e23f83245f314e982bc6d3c5bbfa9cabc6278d83a0327459e014fc45ffa380c4d8fda0177bc3a6411c01ab251015b96e1ac1f09b956fdaf30f30915dae61f2c13f523763a5828761c7c9b65298d1ed963653f082edc2e398d71a3f9fe54bf2a510c102207c9087a89abe8f526c9f9cc4099ca57311ca9f63d97e5b77a0f5e9b428b434d63ace1e6896d47f47b197c446415f26f41fe9e45e9b2ae065bb8995f2cb4af"));
        return p;
      }

      static Integer GetGenerator()
      {
        static Integer g(QByteArray::fromHex("0xbdf740c582bada8f6b6e290733bf345d841a02ef3eaabb75e84ccea4333d64aa4e7086aa79af31f7885bc23434c1436d5244f41fb28ee54d373148ca4f10abd71067d029e9906792089f556af0c69cc0f80236455338a8a3e387ba76bd7f1d2f07c4d30f3b7990753dd979975b6b3c84ce411fd4bf54a75222e4d1ec7afb7575a7d6be25ac939ec1ca1b986ee27290c673953b76f6ea096c09bc9f05040b1e1f7c7f4ddf365fbf8d105c807bec97b5e28ba894c0187367e63e3c52bceb9660355ba06c2fbe1ff046e7cca6a1f86baf4ae500bbf476b2c797f7be101a78d6c6b125807d978fd23263d0a15d906c03ba8b7bbcef677db9aaadc9ea0253142ef778"));
        return g;
      }

      static Integer GetSubgroupSize()
      {
        static Integer q(QByteArray::fromHex("0x6e9d689758f704de752c99ec21a7227510fca88a75c9249e74d82beed951e116a54b6d78d3c2d6f62403ea1a3dba2fbb9f0d578d95cc3c4e6ba2a9b6dff3fd4697fef080521456ee9d8286eddaf91f8d75e6d99201333961f9a0917a0fb711fc1922f98a74c15e369e2ddfd4e55e313c6c1d0193a2cf00a7e22ffd1c0626c7ed00bbde1d3208e00d592880adcb70d60f84dcab7ed79879848aed730f9609fa91bb1d2c143b0e3e4db294c68f6cb1b29f84176e171cc6b8d1fcff2a5f952886081103e4843d44d5f47a9364fce6204ce52b988e54fb1ecbf2dbbd07af4da145a1a6b1d670f344b6a3fa3d8cbe22320af937a0ff4f22f4d957032ddc4caf965a57"));
        return q;
      }

      static bool IsValidKey(const DsaPublicKey &key)
      {
        return key.GetModulus() == GetModulus() &&
               key.GetGenerator() == GetGenerator() &&
               key.GetSubgroupOrder() == GetSubgroupSize();
      }


      static Integer RandomGenerator(CryptoRandom &rand)
      {
        const Integer P = GetModulus();
        const Integer Q = GetSubgroupSize();
        Integer gen;
        do {
          gen = rand.GetInteger(1 << (P.GetBitCount() - 1), P);
        } while (gen.Pow(2, P) == 1 || gen.Pow(Q, P) != 1);
        return gen;
      }


    private:
      const QList<QSharedPointer<DsaPublicKey>> m_client_public_keys;
      const QList<QSharedPointer<DsaPublicKey>> m_server_public_keys;
      const QList<Integer> m_server_randomness;
      const QList<Integer> m_generators;
  };


  struct ClientProof {
      QList<Integer> C;
      QList<Integer> R0;
      QList<Integer> R1;
  };

  struct ServerProof {
      Integer tag;
      Integer c;
      Integer r1;
      Integer r2;
  };

  struct DishonestClientProof {
      int server_id;
      Integer shared_secret;
      DsaPublicKey client_ephemeral_key;
      Integer disclosed_seed;
      Integer t1;
      Integer t2;
      Integer c;
      Integer r;
  };

  struct ClientAuthenticationState {
      ClientAuthenticationState(const int id, QSharedPointer<const DsaPrivateKey> private_key)
        : ephemeral_key(AuthenticationContext::GetModulus(),
                        AuthenticationContext::GetSubgroupSize(),
                        AuthenticationContext::GetGenerator()),
          m_id(id),
          m_private_key(private_key)
      {}

      // These values will be sent to the server to generate a challenge.
      DsaPrivateKey ephemeral_key;
      QList<Integer> commitments;
      Integer initial_linkage_tag;
      QList<Integer> T00;
      QList<Integer> T10;
      QList<Integer> T11;

  private:
      friend class AuthenticationContext;

      // These values should not be sent to the server.
      const int m_id;
      QSharedPointer<const DsaPrivateKey> m_private_key;
      Integer m_secret_product;
      QList<Integer> m_w;
      QList<Integer> m_v0;
      QList<Integer> m_v1;
  };

  struct ServerVerificationState {
      ServerVerificationState(const int id,
                              QSharedPointer<const DsaPrivateKey> private_key,
                              const Integer private_randomness,
                              const DsaPublicKey client_ephemeral_key,
                              const QList<Integer> client_commitments,
                              const Integer initial_linkage_tag,
                              const QList<Integer> T00,
                              const QList<Integer> T10,
                              const QList<Integer> T11)
        : server_id(id),
          server_private(private_key),
          private_randomness(private_randomness),
          client_ephemeral_key(client_ephemeral_key),
          client_commitments(client_commitments),
          initial_linkage_tag(initial_linkage_tag),
          T00(T00),
          T10(T10),
          T11(T11)
      {}

      const int server_id;
      QSharedPointer<const DsaPrivateKey> server_private;
      const Integer private_randomness;

      // The client sends these to get a challenge.
      const DsaPublicKey client_ephemeral_key;
      const QList<Integer> client_commitments;
      const Integer initial_linkage_tag;
      const QList<Integer> T00;
      const QList<Integer> T10;
      const QList<Integer> T11;

      // The actual challenge.
      Integer challenge;

      // Challenge response.
      ClientProof client_proof;

      // Server proofs.
      QList<ServerProof> server_proofs;
  };

}
}
}

#endif
