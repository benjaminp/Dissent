#include <QCoreApplication>
#include <QDebug>

#include "Dissent.hpp"

using namespace Dissent::Crypto::DAGA;
using Dissent::Crypto::CryptoRandom;


static QByteArray SerializeClientChallengeRequest(const ClientAuthenticationState &cas)
{
  QByteArray res;
  QDataStream out(&res, QIODevice::WriteOnly);
  out << cas.ephemeral_key.GetPublicElement();
  out << cas.commitments;
  out << cas.initial_linkage_tag;
  out << cas.T00;
  out << cas.T10;
  out << cas.T11;
  return res;
}

static QByteArray SerializeVerificationMsg(const ClientProof &cp, const QList<ServerProof> server_proofs)
{
  QByteArray res;
  QDataStream out(&res, QIODevice::WriteOnly);
  out << cp.C;
  out << cp.R0;
  out << cp.R1;
  out << static_cast<qint32>(server_proofs.size());
  for (int i = 0; i < server_proofs.size(); i++) {
    const ServerProof &sp = server_proofs.at(i);
    out << sp.tag;
    out << sp.c;
    out << sp.r1;
    out << sp.r2;
  }
  return res;
}

static QList<ServerProof> DeserializeVerificationMsg(const QByteArray msg, ClientProof &cp)
{
  QDataStream in(msg);
  in >> cp.C;
  in >> cp.R0;
  in >> cp.R1;
  QList<ServerProof> server_proofs;
  qint32 nproofs;
  in >> nproofs;
  for (int i = 0; i < nproofs; i++) {
    ServerProof sp;
    in >> sp.tag;
    in >> sp.c;
    in >> sp.r1;
    in >> sp.r2;
    server_proofs.append(sp);
  }
  return server_proofs;
}

class Server {
public:
  Server(int id, QSharedPointer<DsaPrivateKey> key, Integer private_randomness)
    : id(id), key(key), private_randomness(private_randomness)
  {}

  Integer GetPublicRandomness() const {
    const Integer P = AuthenticationContext::GetModulus();
    const Integer G = AuthenticationContext::GetGenerator();
    return G.Pow(private_randomness, P);
  }

  QPair<QPair<Integer, QByteArray>, QSharedPointer<ServerVerificationState>> GenerateChallenge(const QByteArray msg, CryptoRandom &rand) const {
    QDataStream inp(msg);
    QList<Integer> commitments, T00, T10, T11;
    Integer initial_linkage_tag, ephemeral_public_elem;
    inp >> ephemeral_public_elem;
    inp >> commitments;
    inp >> initial_linkage_tag;
    inp >> T00;
    inp >> T10;
    inp >> T11;
    DsaPublicKey ephemeral_key(AuthenticationContext::GetModulus(),
                               AuthenticationContext::GetSubgroupSize(),
                               AuthenticationContext::GetGenerator(),
                               ephemeral_public_elem);
    Integer challenge = rand.GetInteger(0, AuthenticationContext::GetSubgroupSize());
    QByteArray sig = key->Sign(challenge.GetByteArray());
    QSharedPointer<ServerVerificationState> svs(new ServerVerificationState(id,
                                                                            key,
                                                                            private_randomness,
                                                                            ephemeral_key,
                                                                            commitments,
                                                                            initial_linkage_tag,
                                                                            T00,
                                                                            T10,
                                                                            T11));
    return QPair<QPair<Integer, QByteArray>, QSharedPointer<ServerVerificationState>>(QPair<Integer, QByteArray>(challenge, sig), svs);
  }

  Integer ComputeFinalChallenge(const AuthenticationContext &ac,
                                QSharedPointer<ServerVerificationState> svs,
                                const QByteArray msg) const {
    QList<QPair<Integer, QByteArray>> parts;
    QDataStream inp(msg);
    inp >> parts;
    svs->challenge = 0;
    for (int i = 0; i < parts.size(); i++) {
      if (!ac.GetServerPublicKeys()[i]->Verify(parts.at(i).first.GetByteArray(), parts.at(i).second)) {
        qWarning() << "Invalid challenge signature";
        return 0;
      }
      svs->challenge += parts.at(i).first;
      svs->challenge %= AuthenticationContext::GetSubgroupSize();
    }
    return svs->challenge;
  }

  QByteArray ProcessClientAuth(const AuthenticationContext &ac, QSharedPointer<ServerVerificationState> svs, const QByteArray msg, bool last) const {
    svs->server_proofs = DeserializeVerificationMsg(msg, svs->client_proof);
    VerificationResult expected = (last) ? VerificationResult::SUCCESS : VerificationResult::CONTINUE;
    VerificationResult err = ac.ProcessClientAuth(*svs, NULL);
    if (err != expected) {
      qWarning() << "Server " << id << " failed to validate.";
      return QByteArray();
    }
    return SerializeVerificationMsg(svs->client_proof, svs->server_proofs);
  }

  int id;
  QSharedPointer<DsaPrivateKey> key;
  Integer private_randomness;
};

static QList<QSharedPointer<DsaPublicKey>> SlurpKeys(QString dirname, int clamp)
{
  QList<QSharedPointer<DsaPublicKey>> keys;
  // Make sure to sort entries to make this deterministic!
  QDir key_path(dirname);
  foreach (const QString &key_name, key_path.entryList(QDir::Files, QDir::Name)) {
    QString path = key_path.filePath(key_name);
    QSharedPointer<DsaPublicKey> key(new DsaPrivateKey(path));
    if (!key->IsValid() || !AuthenticationContext::IsValidKey(*key)) {
      qWarning() << "Invalid key: " << path;
      continue;
    }
    keys.append(key);
    if (--clamp == 0) {
      break;
    }
  }
  return keys;
}

int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  QStringList args = QCoreApplication::arguments();
  QTextStream qtout(stdout, QIODevice::WriteOnly);

  if (args.size() != 6) {
    qtout << "usage: " << args[0] << " client_key_dir nclients server_key_dir nservers seed\n\n";
    return 2;
  }

  QString client_key_dir = args.at(1);
  QList<QSharedPointer<DsaPublicKey>> client_keys = SlurpKeys(client_key_dir, args.at(2).toInt());
  if (client_keys.size() == 0) {
    qWarning("no DAGA client keys provided");
    return 0;
  }

  QString server_key_dir = args.at(3);
  QList<QSharedPointer<DsaPublicKey>> server_keys = SlurpKeys(server_key_dir, args.at(4).toInt());
  if (server_keys.size() == 0) {
    qWarning("no DAGA server keys provided");
    return 0;
  }

  // This is just shameful.
  QString seed = args.at(5);
  CryptoRandom rand(seed.toUtf8());
  QList<Integer> generators;
  for (int i = 0; i < client_keys.size(); i++) {
    generators.append(AuthenticationContext::RandomGenerator(rand));
  }
  QList<QSharedPointer<Server>> servers;
  QList<Integer> server_public_randomness;
  for (int i = 0; i < server_keys.size(); i++) {
    QSharedPointer<Server> server(new Server(i,
                                             server_keys.at(i).staticCast<DsaPrivateKey>(),
                                             rand.GetInteger(0, AuthenticationContext::GetSubgroupSize())));
    servers.append(server);
    server_public_randomness.append(server->GetPublicRandomness());
  }

  uint64_t client2server = 0, server2server = 0, server2client = 0;
  PrintResourceUsage("daga-start-client");

  AuthenticationContext ac(client_keys,
                           server_keys,
                           server_public_randomness,
                           generators);

  ClientAuthenticationState cas(0, client_keys[0].staticCast<DsaPrivateKey>());
  ac.BeginClientAuth(cas);
  QByteArray req = SerializeClientChallengeRequest(cas);
  client2server += req.size();
  PrintResourceUsage("daga-end-client");
  PrintResourceUsage("daga-start-server");
  QList<QSharedPointer<ServerVerificationState>> server_states;
  QList<QPair<Integer, QByteArray>> challenge_parts;
  for (int i = 0; i < servers.size(); i++) {
    server2server += req.size();
    QPair<QPair<Integer, QByteArray>, QSharedPointer<ServerVerificationState>> pair = servers.at(i)->GenerateChallenge(req, rand);
    challenge_parts.append(pair.first);
    server_states.append(pair.second);
  }
  QByteArray challenge_msg;
  {
    QDataStream out(&challenge_msg, QIODevice::WriteOnly);
    out << challenge_parts;
  }
  Integer final_challenge;
  for (int i = 0; i < servers.size(); i++) {
    server2server += challenge_msg.size();
    final_challenge = servers.at(i)->ComputeFinalChallenge(ac, server_states.at(i), challenge_msg);
    server2server += final_challenge.GetBitCount() / 8;
  }
  PrintResourceUsage("daga-end-server");
  PrintResourceUsage("daga-start-client");
  ClientProof client_proof;
  server2client += final_challenge.GetBitCount() / 8;
  ac.AnswerChallenge(client_proof, cas, final_challenge);

  QByteArray next_msg = SerializeVerificationMsg(client_proof, QList<ServerProof>());
  PrintResourceUsage("daga-end-client");
  PrintResourceUsage("daga-start-server");
  for (int i = 0; i < servers.size(); i++) {
    if (i == 0) {
      client2server += next_msg.size();
    } else {
      server2server += next_msg.size();
    }
    next_msg = servers.at(i)->ProcessClientAuth(ac, server_states.at(i), next_msg, i + 1 == servers.size());
    if (next_msg.isNull()) {
      qWarning("server auth failed");
      return 1;
    }
  }
  server2client += next_msg.size();
  PrintResourceUsage("daga-end-server");

  qDebug() << "c2s: " << client2server << " s2s: " << server2server << " s2c: " << server2client;
  qtout << "success\n";

  return 0;
}
