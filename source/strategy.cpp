/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Native CoreLib lifecycle for the TEE deletion construction. */
#include "TEESecureDeletionAuditStrategy/strategy.h"
#include "TEESecureDeletionAuditStrategy/deletion_state_store.h"

#include "ChordAuditMatrixLib/implementations/crypto/sm9/gt_element.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9/points.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_noncert/hash_utils.h"
#include "ChordAuditMatrixLib/interfaces/audit/artifact_factory.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/in_memory_tags.h"

#include <algorithm>
#include <cereal/archives/binary.hpp>
#include <json/json.h>
#include <map>
#include <numeric>
#include <random>
#include <stdexcept>
#include <utility>

namespace CAMatrix::Audit::Strategies {
namespace {
using namespace CAMatrix::Audit::Core;
using namespace CAMatrix::Audit::Messages;
using SM9CryptoData = CAMatrix::Crypto::SM9::SM9CryptoData;
using G1Point = CAMatrix::Crypto::SM9::G1Point;
using G2Point = CAMatrix::Crypto::SM9::G2Point;
using SM9GTElement = CAMatrix::Crypto::SM9::SM9GTElement;

class TeeSystemPublic final : public AlgoPublicParams {
public:
  G1Point u;

protected:
  void do_serialize(cereal::BinaryOutputArchive &) const override {}
  void do_deserialize(cereal::BinaryInputArchive &) override {}
};
class TeeUserPublic final : public AlgoPublicParams {
public:
  G2Point pk1;
  G2Point pk2;

protected:
  void do_serialize(cereal::BinaryOutputArchive &) const override {}
  void do_deserialize(cereal::BinaryInputArchive &) override {}
};
class TeeUserPrivate final : public AlgoPrivateParams {
public:
  SM9CryptoData sk1;
  SM9CryptoData sk2;

protected:
  void do_serialize(cereal::BinaryOutputArchive &) const override {}
  void do_deserialize(cereal::BinaryInputArchive &) override {}
};

class TeeTag final : public Tag {
public:
  TeeTag() : value(std::make_shared<G1Point>()) { value->setInfinity(); }
  explicit TeeTag(std::shared_ptr<G1Point> point) : value(std::move(point)) {}

  void assign(const Tag &other) override {
    const auto *typed = dynamic_cast<const TeeTag *>(&other);
    if (!typed)
      throw std::runtime_error("TEE tag type mismatch");
    value = typed->value;
  }

  std::shared_ptr<Tag> operator+(const Tag &other) const override {
    const auto *typed = dynamic_cast<const TeeTag *>(&other);
    if (!typed)
      throw std::runtime_error("TEE tag type mismatch");
    return std::make_shared<TeeTag>(
        std::static_pointer_cast<G1Point>(*value + *typed->value));
  }

  bool operator==(const Tag &other) const override {
    const auto *typed = dynamic_cast<const TeeTag *>(&other);
    return typed && value && typed->value && *value == *typed->value;
  }

  std::shared_ptr<G1Point> value;

protected:
  void do_serialize(cereal::BinaryOutputArchive &archive) const override {
    const bool present = static_cast<bool>(value);
    archive(present);
    if (present) {
      const auto raw = value->toRawStruct();
      archive(cereal::binary_data(&raw, sizeof(raw)));
    }
  }

  void do_deserialize(cereal::BinaryInputArchive &archive) override {
    bool present = false;
    archive(present);
    if (!present) {
      value.reset();
      return;
    }
    CAMatrix::Crypto::SM9::SM9PointData raw;
    archive(cereal::binary_data(&raw, sizeof(raw)));
    value = std::make_shared<G1Point>();
    value->setValue(raw);
  }
};

class TeeChallenges final : public Challenges {
public:
  struct Item {
    std::size_t index = 0;
    SM9CryptoData coefficient;
  };
  std::vector<Item> items;
  std::size_t blockCount = 0;
  std::size_t challengeCount = 0;
  std::uint64_t seed = 0;

protected:
  void do_serialize(cereal::BinaryOutputArchive &archive) const override {
    archive(blockCount, challengeCount, seed);
    const auto count = items.size();
    archive(count);
    for (const auto &item : items) {
      archive(item.index, cereal::binary_data(item.coefficient.data(),
                                              item.coefficient.size()));
    }
  }

  void do_deserialize(cereal::BinaryInputArchive &archive) override {
    archive(blockCount, challengeCount, seed);
    std::size_t count = 0;
    archive(count);
    items.resize(count);
    for (auto &item : items) {
      archive(item.index, cereal::binary_data(item.coefficient.data(),
                                              item.coefficient.size()));
    }
  }
};

class TeeProof final : public Proves {
public:
  SM9CryptoData muHat;
  std::shared_ptr<TeeTag> sigma;

protected:
  void do_serialize(cereal::BinaryOutputArchive &archive) const override {
    archive(cereal::binary_data(muHat.data(), muHat.size()));
    const bool present = sigma && sigma->value;
    archive(present);
    if (present) {
      const auto raw = sigma->value->toRawStruct();
      archive(cereal::binary_data(&raw, sizeof(raw)));
    }
  }

  void do_deserialize(cereal::BinaryInputArchive &archive) override {
    archive(cereal::binary_data(muHat.data(), muHat.size()));
    bool present = false;
    archive(present);
    if (!present) {
      sigma.reset();
      return;
    }
    CAMatrix::Crypto::SM9::SM9PointData raw;
    archive(cereal::binary_data(&raw, sizeof(raw)));
    auto point = std::make_shared<G1Point>();
    point->setValue(raw);
    sigma = std::make_shared<TeeTag>(std::move(point));
  }
};

class TeeArtifactFactory final : public AuditStrategyArtifactFactory {
public:
  AuditArtifactVariant createArtifact(AuditArtifactKind kind) const override {
    switch (kind) {
    case AuditArtifactKind::AlgorithmPublicParams:
      return std::static_pointer_cast<AlgoPublicParams>(
          std::make_shared<TeeSystemPublic>());
    case AuditArtifactKind::UserPublicParams:
      return std::static_pointer_cast<AlgoPublicParams>(
          std::make_shared<TeeUserPublic>());
    case AuditArtifactKind::UserPrivateParams:
      return std::static_pointer_cast<AlgoPrivateParams>(
          std::make_shared<TeeUserPrivate>());
    case AuditArtifactKind::Tag:
      return std::static_pointer_cast<Tag>(std::make_shared<TeeTag>());
    case AuditArtifactKind::Challenges:
      return std::static_pointer_cast<Challenges>(
          std::make_shared<TeeChallenges>());
    case AuditArtifactKind::Proves:
      return std::static_pointer_cast<Proves>(std::make_shared<TeeProof>());
    case AuditArtifactKind::DynamicBlockMetadata:
      return std::static_pointer_cast<BlockMetadata>(
          std::make_shared<TEEDeletion::DeletionBlockMetadata>());
    default:
      throw std::runtime_error("unsupported TEE artifact kind");
    }
  }
};
struct TeeTagsExt final : StageExtBase {
  std::string fileId;
  std::shared_ptr<TeeSystemPublic> system;
  std::shared_ptr<TeeUserPublic> pub;
  std::shared_ptr<TeeUserPrivate> priv;
};
struct TeeMaintainExt final : StageExtBase {
  std::string fileId;
  std::vector<std::size_t> indices;
  std::string seed;
  std::shared_ptr<TeeSystemPublic> system;
  std::shared_ptr<TeeUserPrivate> priv;
};
struct TeeChallengeExt final : StageExtBase {
  std::string fileId;
  std::size_t challengeCount = 0;
  std::uint64_t seed = 0;
};
struct TeeProofExt final : StageExtBase {
  std::string fileId;
  bool replay = false;
};
struct TeeVerifyExt final : StageExtBase {
  std::string fileId;
  std::shared_ptr<TeeSystemPublic> system;
  std::shared_ptr<TeeUserPublic> pub;
};
struct NativeDeletionFile {
  std::vector<SM9CryptoData> values, preDeleteValues;
  TagsPtr tags;
  std::vector<G1Point> preDeleteTags;
  std::vector<std::size_t> deletedIndices;
};
std::map<std::string, NativeDeletionFile> files;
std::string activeFileId;

SM9CryptoData hashBlockToScalar(const CAMatrix::Crypto::CryptoArray &payload) {
  SM9CryptoData value;
  value.mapToField(payload);
  return value;
}

G1Point computeBlockHash(const std::string &fileId, std::size_t blockIndex) {
  CAMatrix::Crypto::CryptoArray data;
  data.insert(data.end(), fileId.begin(), fileId.end());
  for (int shift = 56; shift >= 0; shift -= 8) {
    data.push_back(static_cast<std::uint8_t>((blockIndex >> shift) & 0xffU));
  }
  return CAMatrix::Crypto::SM9Noncert::hashBlock(data);
}

SM9CryptoData hashScalar(const std::string &text) {
  SM9CryptoData x;
  x.mapToField(reinterpret_cast<const std::uint8_t *>(text.data()),
               text.size());
  if (x.isZero())
    x.setOne();
  return x;
}
G1Point mul(const G1Point &p, const SM9CryptoData &x) {
  return *std::static_pointer_cast<G1Point>(p * x);
}
G2Point mul(const G2Point &p, const SM9CryptoData &x) {
  return *std::static_pointer_cast<G2Point>(p * x);
}
G1Point add(const G1Point &a, const G1Point &b) {
  return *std::static_pointer_cast<G1Point>(a + b);
}
std::string scalarText(const SM9CryptoData &value) {
  const auto bytes = value.serialize();
  return std::string(reinterpret_cast<const char *>(bytes.data()),
                     bytes.size());
}
G1Point h2(const std::string &fid, std::size_t i, const SM9CryptoData &value) {
  return computeBlockHash(
      fid + ":OD:" + std::to_string(i) + ":" + scalarText(value), 1);
}
std::vector<std::size_t> indices(const Json::Value &root) {
  const auto &raw = root.isMember("targetBlockIndices")
                        ? root["targetBlockIndices"]
                        : root["blockIndices"];
  std::vector<std::size_t> result;
  if (!raw.isArray())
    return result;
  for (const auto &value : raw) {
    auto i = static_cast<std::size_t>(value.asUInt64());
    result.push_back(i == 0 ? 1 : i);
  }
  return result;
}
} // namespace

CAMatrix::Audit::Messages::Capabilities
TEESecureDeletionAuditStrategy::caps() const {
  return CAMatrix::Audit::Messages::Capabilities::DynamicUpdate;
}
StateMaintenanceParty
TEESecureDeletionAuditStrategy::stateMaintenanceParty() const {
  return StateMaintenanceParty::Shared;
}
std::shared_ptr<DynamicPdpStateStore>
TEESecureDeletionAuditStrategy::createStateStore(
    BlockMetadataFactory factory) const {
  return std::make_shared<TEEDeletion::DeletionStateStore>(std::move(factory));
}
void TEESecureDeletionAuditStrategy::setAlgorithm(
    CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm) {
  algorithm_ = std::move(algorithm);
}
const AuditStrategyArtifactFactory &
TEESecureDeletionAuditStrategy::artifactFactory() const {
  static TeeArtifactFactory factory;
  return factory;
}

InitializeAlgorithmResult TEESecureDeletionAuditStrategy::initializeAlgorithm(
    const InitializeAlgorithmRequest &) {
  InitializeAlgorithmResult out;
  auto pub = std::make_shared<TeeSystemPublic>();
  pub->u = computeBlockHash("TEE-SECURE-DELETION-U", 1);
  out.ok = true;
  out.publicParams = pub;
  return out;
}
GenerateKeysResult
TEESecureDeletionAuditStrategy::generateKeys(const GenerateKeysRequest &) {
  GenerateKeysResult out;
  auto priv = std::make_shared<TeeUserPrivate>();
  priv->sk1 = hashScalar("TEE:sk1");
  priv->sk2 = hashScalar("TEE:sk2");
  auto pub = std::make_shared<TeeUserPublic>();
  pub->pk1 = mul(G2Point::generator(), priv->sk1);
  pub->pk2 = mul(G2Point::generator(), priv->sk2);
  out.ok = true;
  out.publicParams = pub;
  out.privateParams = priv;
  return out;
}
GenerateTagsResult
TEESecureDeletionAuditStrategy::generateTags(const GenerateTagsRequest &input) {
  GenerateTagsResult out;
  auto ext = std::dynamic_pointer_cast<TeeTagsExt>(input.ext);
  if (!ext || !input.blocks || !ext->system || !ext->priv)
    return out;
  auto tags =
      std::make_shared<InMemoryTags>([] { return std::make_shared<TeeTag>(); });
  NativeDeletionFile file;
  for (std::size_t offset = 0; offset < input.blocks->availableBlockCount();
       ++offset) {
    const auto value = hashBlockToScalar(
        CAMatrix::Crypto::CryptoArray(input.blocks->block(offset)));
    const auto msg = add(computeBlockHash(ext->fileId, offset + 1),
                         mul(ext->system->u, value));
    tags->set(offset, std::make_shared<TeeTag>(
                          std::make_shared<G1Point>(mul(msg, ext->priv->sk1))));
    file.values.push_back(value);
  }
  file.tags = tags;
  files[ext->fileId] = file;
  activeFileId = ext->fileId;
  out.tags = tags;
  out.ext = ext;
  return out;
}
MaintainResult
TEESecureDeletionAuditStrategy::maintenance(const MaintainRequest &input) {
  MaintainResult out;
  auto ext = std::dynamic_pointer_cast<TeeMaintainExt>(input.ext);
  if (!ext || input.type != MaintenanceOpType::Delete || !ext->system ||
      !ext->priv)
    return out;
  auto found = files.find(ext->fileId);
  if (found == files.end())
    return out;
  auto &file = found->second;
  file.preDeleteValues = file.values;
  file.preDeleteTags.clear();
  for (std::size_t offset = 0; offset < file.values.size(); ++offset) {
    const auto previous =
        std::dynamic_pointer_cast<TeeTag>(file.tags->getByIndex(offset));
    file.preDeleteTags.push_back(*previous->value);
  }
  const auto seed =
      hashScalar(ext->seed.empty() ? ext->fileId + ":seed" : ext->seed);
  const auto sigmaSeed = mul(mul(ext->system->u, seed), ext->priv->sk1);
  const auto R = mul(ext->system->u, ext->priv->sk1);
  for (const auto index : ext->indices) {
    if (index == 0 || index > file.values.size())
      throw std::out_of_range("TEE deletion index out of range");
    const auto off = index - 1;
    const auto r = hashScalar(ext->fileId + ":r:" + std::to_string(index) +
                              ":" + scalarText(file.values[off]));
    const auto od = *std::static_pointer_cast<SM9CryptoData>(seed + r);
    const auto sigma = add(add(sigmaSeed, mul(R, r)),
                           mul(h2(ext->fileId, index, od), ext->priv->sk2));
    file.values[off] = od;
    file.tags->set(off,
                   std::make_shared<TeeTag>(std::make_shared<G1Point>(sigma)));
    if (std::find(file.deletedIndices.begin(), file.deletedIndices.end(),
                  index) == file.deletedIndices.end())
      file.deletedIndices.push_back(index);
  }
  activeFileId = ext->fileId;
  out.tags = file.tags;
  out.ext = ext;
  return out;
}
GenerateChallengesResult TEESecureDeletionAuditStrategy::generateChallenges(
    const GenerateChallengesRequest &input) {
  GenerateChallengesResult out;
  auto ext = std::dynamic_pointer_cast<TeeChallengeExt>(input.ext);
  if (!ext)
    return out;
  const auto found = files.find(ext->fileId);
  if (found == files.end() || found->second.deletedIndices.empty())
    return out;
  std::vector<std::size_t> selected(found->second.values.size());
  std::iota(selected.begin(), selected.end(), 1);
  std::mt19937_64 rng(ext->seed);
  std::shuffle(selected.begin(), selected.end(), rng);
  selected.resize(std::min(selected.size(), ext->challengeCount
                                                ? ext->challengeCount
                                                : selected.size()));
  auto q = std::make_shared<TeeChallenges>();
  q->blockCount = found->second.values.size();
  q->challengeCount = selected.size();
  q->seed = ext->seed;
  for (const auto index : selected) {
    TeeChallenges::Item item;
    item.index = index;
    item.coefficient.setOne();
    q->items.push_back(item);
  }
  out.challenges = q;
  out.ext = ext;
  return out;
}
GenerateProofsResult TEESecureDeletionAuditStrategy::generateProofs(
    const GenerateProofsRequest &input) {
  GenerateProofsResult out;
  auto ext = std::dynamic_pointer_cast<TeeProofExt>(input.ext);
  auto q = std::dynamic_pointer_cast<TeeChallenges>(input.challenges);
  if (!ext || !q || q->items.empty())
    return out;
  const auto found = files.find(ext->fileId);
  if (found == files.end())
    return out;
  const auto &file = found->second;
  SM9CryptoData M;
  std::shared_ptr<TeeTag> omega;
  for (const auto &item : q->items) {
    if (item.index == 0 || item.index > file.values.size())
      return out;
    const auto off = item.index - 1;
    const bool stale =
        ext->replay &&
        std::find(file.deletedIndices.begin(), file.deletedIndices.end(),
                  item.index) != file.deletedIndices.end();
    const auto &value = stale ? file.preDeleteValues[off] : file.values[off];
    M.assign(*std::static_pointer_cast<SM9CryptoData>(M + value));
    auto tag =
        stale ? std::make_shared<TeeTag>(
                    std::make_shared<G1Point>(file.preDeleteTags[off]))
              : std::dynamic_pointer_cast<TeeTag>(file.tags->getByIndex(off));
    omega = omega ? std::dynamic_pointer_cast<TeeTag>(*omega + *tag)
                  : std::make_shared<TeeTag>(tag->value);
  }
  auto proof = std::make_shared<TeeProof>();
  proof->muHat = M;
  proof->sigma = omega;
  out.proves = proof;
  out.ext = ext;
  return out;
}
VerifyProofsResult
TEESecureDeletionAuditStrategy::verifyProofs(const VerifyProofsRequest &input) {
  VerifyProofsResult out;
  if (input.challenges.empty() || input.proves.empty()) {
    out.reason = "missing deletion proof";
    return out;
  }
  auto ext = std::dynamic_pointer_cast<TeeVerifyExt>(input.ext);
  auto q = std::dynamic_pointer_cast<TeeChallenges>(input.challenges.front());
  auto proof = std::dynamic_pointer_cast<TeeProof>(input.proves.front());
  auto omega = proof ? proof->sigma : nullptr;
  const auto found = files.find(ext ? ext->fileId : "");
  if (!ext || !ext->system || !ext->pub || !q || !proof || !omega ||
      !omega->value || found == files.end()) {
    out.reason = "invalid TEE deletion evidence";
    return out;
  }
  G1Point hashes;
  hashes.setInfinity();
  for (const auto &item : q->items) {
    if (item.index == 0 || item.index > found->second.values.size()) {
      out.reason = "invalid deletion index";
      return out;
    }
    hashes.assign(add(hashes, h2(ext->fileId, item.index,
                                 found->second.values[item.index - 1])));
  }
  SM9GTElement left, first, second;
  left.pairing(*omega->value, G2Point::generator());
  first.pairing(mul(ext->system->u, proof->muHat), ext->pub->pk1);
  second.pairing(hashes, ext->pub->pk2);
  auto right = first * second;
  out.ok = right && (left == *right);
  out.reason = out.ok ? "" : "TEE deletion pairing equation rejected";
  return out;
}
AuditRequestVariantPtr
TEESecureDeletionAuditStrategy::createRequest(AuditOperation op,
                                              const AuditOperationContext &ctx,
                                              const RawInput &input) {
  switch (op) {
  case AuditOperation::AlgorithmInit: {
    auto r = std::make_shared<InitializeAlgorithmRequest>();
    r->ext = std::make_shared<StageExtBase>();
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::KeyGeneration: {
    auto r = std::make_shared<GenerateKeysRequest>();
    r->ext = std::make_shared<StageExtBase>();
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::GenerateTags: {
    auto r = std::make_shared<GenerateTagsRequest>();
    auto ext = std::make_shared<TeeTagsExt>();
    auto data = input.requireCustom<AuditDataMap>(op);
    r->blocks = data->getRequired<
        std::shared_ptr<CAMatrix::Audit::Data::AuditBlockSource>>("blocks");
    ext->fileId = data->getRequired<std::string>("fileId");
    ext->system = std::dynamic_pointer_cast<TeeSystemPublic>(
        ctx.initializeAlgorithmResult->publicParams);
    ext->pub = std::dynamic_pointer_cast<TeeUserPublic>(
        ctx.generateKeysResult->publicParams);
    ext->priv = std::dynamic_pointer_cast<TeeUserPrivate>(
        ctx.generateKeysResult->privateParams);
    r->ext = ext;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::Maintenance: {
    const auto root = input.requireJson(op);
    auto r = std::make_shared<MaintainRequest>();
    r->type = MaintenanceOpType::Delete;
    auto ext = std::make_shared<TeeMaintainExt>();
    ext->fileId = root.get("fileId", activeFileId).asString();
    ext->indices = indices(root);
    ext->seed = root.get("seed", ext->fileId + ":seed").asString();
    ext->system = std::dynamic_pointer_cast<TeeSystemPublic>(
        ctx.initializeAlgorithmResult->publicParams);
    ext->priv = std::dynamic_pointer_cast<TeeUserPrivate>(
        ctx.generateKeysResult->privateParams);
    r->tags = ctx.generateTagsResult->tags;
    r->ext = ext;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::ChallengeGen: {
    const auto root = input.requireJson(op);
    auto r = std::make_shared<GenerateChallengesRequest>();
    auto ext = std::make_shared<TeeChallengeExt>();
    ext->fileId = root.get("fileId", activeFileId).asString();
    ext->challengeCount =
        static_cast<std::size_t>(root.get("challengeCount", 0).asUInt64());
    ext->seed = root.get("seed", 42).asUInt64();
    r->tags = ctx.maintainResult ? ctx.maintainResult->tags
                                 : ctx.generateTagsResult->tags;
    r->ext = ext;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::ProofGen: {
    auto r = std::make_shared<GenerateProofsRequest>();
    r->challenges = ctx.generateChallengesResult->challenges;
    auto ext = std::make_shared<TeeProofExt>();
    ext->fileId = activeFileId;
    auto data = input.requireCustom<AuditDataMap>(op);
    ext->replay = data->getOptional<bool>("adversarialReplay").value_or(false);
    r->ext = ext;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::ProofVerify: {
    const auto root = input.requireJson(op);
    auto r = std::make_shared<VerifyProofsRequest>();
    r->challenges = {ctx.generateChallengesResult->challenges};
    r->proves = {ctx.generateProofsResult->proves};
    auto ext = std::make_shared<TeeVerifyExt>();
    ext->fileId = root.get("fileId", activeFileId).asString();
    ext->system = std::dynamic_pointer_cast<TeeSystemPublic>(
        ctx.initializeAlgorithmResult->publicParams);
    ext->pub = std::dynamic_pointer_cast<TeeUserPublic>(
        ctx.generateKeysResult->publicParams);
    r->ext = ext;
    return std::make_shared<AuditRequestVariant>(r);
  }
  }
  throw std::runtime_error("unsupported TEE deletion operation");
}

std::uint64_t TEESecureDeletionAuditStrategy::attestationBinding(
    const std::string &fileId, const std::vector<std::size_t> &indices,
    const std::vector<std::uint8_t> &teeKey) {
  if (teeKey.empty())
    throw std::invalid_argument("TEE key share must not be empty");
  std::uint64_t value = 0xcbf29ce484222325ULL;
  const auto mix = [&value](std::uint8_t byte) {
    value = (value ^ byte) * 0x100000001b3ULL;
  };
  for (const auto c : fileId)
    mix(static_cast<std::uint8_t>(c));
  for (const auto i : indices)
    for (unsigned shift = 0; shift < 64; shift += 8)
      mix(static_cast<std::uint8_t>(i >> shift));
  for (const auto byte : teeKey)
    mix(byte);
  return value;
}
std::vector<std::vector<std::uint8_t>>
TEESecureDeletionAuditStrategy::teeOverwrite(
    const std::vector<std::vector<std::uint8_t>> &blocks,
    const std::vector<std::size_t> &ids,
    const std::vector<std::uint8_t> &userKey,
    const std::vector<std::uint8_t> &teeKey, const std::string &fid) {
  auto result = blocks;
  teeOverwriteInPlace(result, ids, userKey, teeKey, fid);
  return result;
}
void TEESecureDeletionAuditStrategy::teeOverwriteInPlace(
    std::vector<std::vector<std::uint8_t>> &blocks,
    const std::vector<std::size_t> &ids,
    const std::vector<std::uint8_t> &userKey,
    const std::vector<std::uint8_t> &teeKey, const std::string &fid) {
  if (userKey.empty() || teeKey.empty())
    throw std::invalid_argument("both deletion key shares are required");
  const auto bind = attestationBinding(fid, ids, teeKey);
  for (const auto index : ids) {
    if (index == 0 || index > blocks.size())
      throw std::out_of_range("TEE target index out of range");
    auto &block = blocks[index - 1];
    for (std::size_t byte = 0; byte < block.size(); ++byte) {
      auto state = bind ^ (index * 0x9e3779b97f4a7c15ULL) ^
                   (byte * 0xbf58476d1ce4e5b9ULL);
      state ^=
          static_cast<std::uint64_t>(userKey[(byte + index) % userKey.size()])
          << ((byte % 8) * 8);
      block[byte] = static_cast<std::uint8_t>(
          state ^ (state >> 25) ^ teeKey[(byte + state) % teeKey.size()]);
    }
  }
}
} // namespace CAMatrix::Audit::Strategies
namespace CAMatrix::Audit::Core {
extern "C" AuditStrategy *create_audit_strategy() noexcept {
  return new CAMatrix::Audit::Strategies::TEESecureDeletionAuditStrategy();
}
extern "C" void destroy_audit_strategy(AuditStrategy *strategy) noexcept {
  delete strategy;
}
} // namespace CAMatrix::Audit::Core
