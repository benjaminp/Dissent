#ifndef DISSENT_TESTS_SHUFFLE_ROUND_HELPERS_H_GUARD
#define DISSENT_TESTS_SHUFFLE_ROUND_HELPERS_H_GUARD

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Anonymity;
    using namespace Dissent::Connections;
    using namespace Dissent::Crypto;
    using namespace Dissent::Messaging;
    using namespace Dissent::Utils;
  }

  class ShuffleRoundBadInnerPrivateKey : public ShuffleRound {
    public:
      ShuffleRoundBadInnerPrivateKey(const Group &group, const Group &shufflers,
          const Id &local_id, const Id &session_id, const Id &round_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, shufflers, local_id, session_id, round_id, ct, rpc,
            signing_key, data)
      { }

      virtual ~ShuffleRoundBadInnerPrivateKey() {}

      inline static Round *Create(const Group &group, const Group &shufflers,
          const Id &local_id, const Id &session_id, const Id &round_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key, const QByteArray &data)
      {
        return new ShuffleRoundBadInnerPrivateKey(group, shufflers, local_id, session_id,
            round_id, ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id,
          CreateGroupGenerator cgg)
      {
        return new Session(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, 
                      ShuffleRoundBadInnerPrivateKey::Create, node->key,
                      ShuffleRound::DefaultData, cgg);
      }

      virtual void BroadcastPrivateKey()
      {
        qDebug() << GetActiveGroup().GetIndex(GetLocalId()) <<
          GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
          ": received sufficient go messages, broadcasting private key.";

        Library *lib = CryptoFactory::GetInstance().GetLibrary();
        AsymmetricKey *tmp = lib->CreatePrivateKey();

        QByteArray msg;
        QDataStream stream(&msg, QIODevice::WriteOnly);
        stream << PrivateKey << GetRoundId().GetByteArray() << tmp->GetByteArray();

        Broadcast(msg);
        int idx = GetActiveGroup().GetIndex(GetLocalId());
        delete _private_inner_keys[idx];
        _private_inner_keys[idx] = lib->LoadPrivateKeyFromByteArray(_inner_key->GetByteArray());
      }
  };

  class ShuffleRoundMessageDuplicator : public ShuffleRound {
    public:
      ShuffleRoundMessageDuplicator(const Group &group, const Group &shufflers,
          const Id &local_id, const Id &session_id, const Id &round_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, shufflers, local_id, session_id, round_id, ct, rpc,
            signing_key, data)
      { }

      virtual ~ShuffleRoundMessageDuplicator() {}

      inline static Round *Create(const Group &group, const Group &shufflers,
          const Id &local_id, const Id &session_id, const Id &round_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key, const QByteArray &data)
      {
        return new ShuffleRoundMessageDuplicator(group, shufflers, local_id, session_id,
            round_id, ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id,
          CreateGroupGenerator cgg)
      {
        return new Session(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, 
                      ShuffleRoundMessageDuplicator::Create, node->key,
                      ShuffleRound::DefaultData, cgg);
      }

    protected:
      virtual void Shuffle()
      {
        _state = Shuffling;
        qDebug() << GetActiveGroup().GetIndex(GetLocalId()) <<
          GetGroup().GetIndex(GetLocalId()) << ": shuffling";
      
        for(int idx = 0; idx < _shuffle_ciphertext.count(); idx++) {
          for(int jdx = 0; jdx < _shuffle_ciphertext.count(); jdx++) {
            if(idx == jdx) {
              continue;
            }
            if(_shuffle_ciphertext[idx] != _shuffle_ciphertext[jdx]) {
              continue;
            }
            qWarning() << "Found duplicate cipher texts... blaming";
            StartBlame();
            return;
          }
        }

        int x = Random::GetInstance().GetInt(0, _shuffle_ciphertext.count());
        int y = Random::GetInstance().GetInt(0, _shuffle_ciphertext.count());
        while(y == x) {
          y = Random::GetInstance().GetInt(0, _shuffle_ciphertext.count());
        }

        _shuffle_ciphertext[x] = _shuffle_ciphertext[y];
  
        QVector<int> bad;
        OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
        if(!oe->Decrypt(_outer_key.data(), _shuffle_ciphertext,
              _shuffle_cleartext, &bad))
        {
          qWarning() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
            ": failed to decrypt layer due to block at indexes" << bad;
          StartBlame();
          return; 
        } 
        
        oe->RandomizeBlocks(_shuffle_cleartext);
        
        const Id &next = GetActiveGroup().Next(GetLocalId());
        MessageType mtype = (next == Id::Zero) ? EncryptedData : ShuffleData;
        
        QByteArray msg;
        QDataStream out_stream(&msg, QIODevice::WriteOnly);
        out_stream << mtype << GetRoundId().GetByteArray() << _shuffle_cleartext;
          
        _state = WaitingForEncryptedInnerData;
      
        if(mtype == EncryptedData) {
          Broadcast(msg);
          _encrypted_data = _shuffle_cleartext;
        } else {
          Send(msg, next);
        }
      }
  };

  class ShuffleRoundMessageSwitcher : public ShuffleRound {
    public:
      ShuffleRoundMessageSwitcher(const Group &group, const Group &shufflers,
          const Id &local_id, const Id &session_id, const Id &round_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, shufflers, local_id, session_id, round_id, ct, rpc,
            signing_key, data)
      { }

      virtual ~ShuffleRoundMessageSwitcher() {}

      inline static Round *Create(const Group &group,
          const Group &shufflers, const Id &local_id, const Id &session_id,
          const Id &round_id, const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key, const QByteArray &data)
      {
        return new ShuffleRoundMessageSwitcher(group, shufflers, local_id, session_id,
            round_id, ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id, CreateGroupGenerator cgg)
      {
        return new Session(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, 
                      ShuffleRoundMessageSwitcher::Create, node->key,
                      ShuffleRound::DefaultData, cgg);
      }

    protected:
      virtual void Shuffle()
      {
        QVector<AsymmetricKey *> outer_keys;
        for(int idx = GetActiveGroup().Count() - 1; idx >= GetActiveGroup().GetIndex(GetLocalId()); idx--) {
          int kidx = CalculateKidx(idx);
          outer_keys.append(_public_outer_keys[kidx]);
        }

        QByteArray data = ShuffleRound::DefaultData;
        QByteArray inner_ct, outer_ct;
        OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
        oe->Encrypt(_public_inner_keys, data, inner_ct, 0);
        oe->Encrypt(outer_keys, inner_ct, outer_ct, 0);

        int x = Random::GetInstance().GetInt(0, _shuffle_ciphertext.count());
        _shuffle_ciphertext[x] = outer_ct;

        ShuffleRound::Shuffle();
      }
  };

  class ShuffleRoundFalseBlame : public ShuffleRound {
    public:
      ShuffleRoundFalseBlame(const Group &group, const Group &shufflers, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, shufflers, local_id, session_id, round_id, ct, rpc, signing_key, data) { }

      virtual ~ShuffleRoundFalseBlame() {}

      inline static Round *Create(const Group &group, const Group &shufflers,
          const Id &local_id, const Id &session_id, const Id &round_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key, const QByteArray &data)
      {
        return new ShuffleRoundFalseBlame(group, shufflers, local_id, session_id,
            round_id, ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id,
          CreateGroupGenerator cgg)
      {
        return new Session(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, 
                      ShuffleRoundFalseBlame::Create, node->key,
                      ShuffleRound::DefaultData, cgg);
      }

    protected:
      virtual void Shuffle()
      {
        StartBlame();
      }
  };

  class ShuffleRoundFalseNoGo : public ShuffleRound {
    public:
      ShuffleRoundFalseNoGo(const Group &group, const Group &shufflers, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, shufflers, local_id, session_id, round_id, ct, rpc, signing_key, data) { }

      virtual ~ShuffleRoundFalseNoGo() {}

      inline static Round *Create(const Group &group, const Group &shufflers,
          const Id &local_id, const Id &session_id, const Id &round_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key, const QByteArray &data)
      {
        return new ShuffleRoundFalseNoGo(group, shufflers, local_id, session_id, round_id,
            ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id,
          CreateGroupGenerator cgg)
      {
        return new Session(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, 
                      ShuffleRoundFalseNoGo::Create, node->key,
                      ShuffleRound::DefaultData, cgg);
      }

    protected:
      virtual void Verify()
      {
        MessageType mtype = NoGoMessage;
        QByteArray msg;
        QDataStream out_stream(&msg, QIODevice::WriteOnly);
        out_stream << mtype << GetRoundId();
        Broadcast(msg);
        StartBlame();
      }
  };

  class ShuffleRoundInvalidOuterEncryption : public ShuffleRound {
    public:
      ShuffleRoundInvalidOuterEncryption(const Group &group, const Group &shufflers, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          const QByteArray &data = DefaultData) :
        ShuffleRound(group, shufflers, local_id, session_id, round_id, ct, rpc, signing_key, data) { }

      virtual ~ShuffleRoundInvalidOuterEncryption() {}

      inline static Round *Create(const Group &group, const Group &shufflers,
          const Id &local_id, const Id &session_id, const Id &round_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key, const QByteArray &data)
      {
        return new ShuffleRoundInvalidOuterEncryption(group, shufflers, local_id, session_id, round_id,
            ct, rpc, signing_key, data);
      }

      inline static Session *CreateSession(TestNode *node, const Group &group,
          const Id &leader_id, const Id &session_id,
          CreateGroupGenerator cgg)
      {
        return new Session(group, node->cm.GetId(), leader_id, session_id,
                      node->cm.GetConnectionTable(), node->rpc, 
                      ShuffleRoundInvalidOuterEncryption::Create, node->key,
                      ShuffleRound::DefaultData, cgg);
      }

    protected:
      virtual void SubmitData()
      {
        _state = DataSubmission;

        OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
        oe->Encrypt(_public_inner_keys, PrepareData(), _inner_ciphertext, 0);

        int count = Random::GetInstance().GetInt(0, GetActiveGroup().Count());
        int opposite = CalculateKidx(count);
        if(count == opposite) {
          opposite = (opposite + 1) % GetActiveGroup().Count();
        }

        AsymmetricKey *tmp = _public_outer_keys[opposite];
        _public_outer_keys[opposite] = _public_outer_keys[count];
        oe->Encrypt(_public_outer_keys, _inner_ciphertext, _outer_ciphertext, 0);
        _public_outer_keys[opposite] = tmp;

        QByteArray msg;
        QDataStream stream(&msg, QIODevice::WriteOnly);
        stream << Data << GetRoundId().GetByteArray() << _outer_ciphertext;

        _state = WaitingForShuffle;
        Send(msg, GetActiveGroup().GetId(0));
      }
  };
}
}

#endif
